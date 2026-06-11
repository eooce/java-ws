import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.ReferenceCountUtil;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import io.github.cdimascio.dotenv.Dotenv;

public class App {
    
    // 优先从.env文件获取，没有则使用系统环境变量
    private static String UUID;
    private static String NEZHA_SERVER;
    private static String NEZHA_PORT;
    private static String NEZHA_KEY;
    private static String DOMAIN;
    private static String SUB_PATH;
    private static String NAME;
    private static String WSPATH;
    private static int PORT;
    private static boolean AUTO_ACCESS;
    private static boolean DEBUG;
    
    private static String PROTOCOL_UUID;
    private static byte[] UUID_BYTES;
    
    private static String currentDomain;
    private static int currentPort = 443;
    private static String tls = "tls";
    private static String isp = "Unknown";
    
    private static final List<String> BLOCKED_DOMAINS = Arrays.asList(
            "speedtest.net", "fast.com", "speedtest.cn", "speed.cloudflare.com", 
            "speedof.me", "testmy.net", "bandwidth.place", "speed.io", 
            "librespeed.org", "speedcheck.org");
    private static final List<String> TLS_PORTS = Arrays.asList(
            "443", "8443", "2096", "2087", "2083", "2053");
    
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private static final Map<String, String> dnsCache = new ConcurrentHashMap<>();
    private static final Map<String, Long> dnsCacheTime = new ConcurrentHashMap<>();
    private static final long DNS_CACHE_TTL = 300000;
    
    private static Process nezhaProcess = null;
    
    // 日志级别控制
    private static boolean SILENT_MODE = true; 
    
    private static void log(String level, String msg) {
        if (SILENT_MODE && !level.equals("INFO")) return;  
        System.out.println(new Date() + " - " + level + " - " + msg);
    }
    
    private static void info(String msg) { log("INFO", msg); }
    private static void error(String msg) { log("ERROR", msg); }
    private static void error(String msg, Throwable t) { 
        log("ERROR", msg);
        if (DEBUG) t.printStackTrace();
    }
    private static void debug(String msg) { if (DEBUG) log("DEBUG", msg); }
    
    private static void loadConfig() {
        // 先尝试加载 .env 文件
        Map<String, String> envFromFile = new HashMap<>();
        try {
            Path envPath = Paths.get(".env");
            if (Files.exists(envPath)) {
                Dotenv dotenv = Dotenv.configure()
                        .directory(".")
                        .filename(".env")
                        .ignoreIfMissing()
                        .load();
                
                dotenv.entries().forEach(entry -> envFromFile.put(entry.getKey(), entry.getValue()));
                // info("✅ .env file loaded: " + envFromFile.size() + " variables");
            } else {
                debug("No .env file found, using default environment variables");
            }
        } catch (Exception e) {
            debug("Failed to load .env file: " + e.getMessage());
        }
        
        // 默认值变量
        UUID = getEnvValue(envFromFile, "UUID", "7bd180e8-1142-4387-93f5-03e8d750a896");
        NEZHA_SERVER = getEnvValue(envFromFile, "NEZHA_SERVER", "");
        NEZHA_PORT = getEnvValue(envFromFile, "NEZHA_PORT", "");
        NEZHA_KEY = getEnvValue(envFromFile, "NEZHA_KEY", "");
        DOMAIN = getEnvValue(envFromFile, "DOMAIN", "");
        SUB_PATH = getEnvValue(envFromFile, "SUB_PATH", "sub");
        NAME = getEnvValue(envFromFile, "NAME", "");
        
        // 处理WSPATH
        String wspathFromEnv = getEnvValue(envFromFile, "WSPATH", null);
        if (wspathFromEnv != null) {
            WSPATH = wspathFromEnv;
        } else {
            WSPATH = UUID.substring(0, 8);
        }
        
        // 处理端口
        String portStr = getEnvValue(envFromFile, "SERVER_PORT", null);
        if (portStr == null) {
            portStr = getEnvValue(envFromFile, "PORT", "3000");
        }
        PORT = Integer.parseInt(portStr);
        
        // 处理布尔值
        AUTO_ACCESS = Boolean.parseBoolean(getEnvValue(envFromFile, "AUTO_ACCESS", "false"));
        DEBUG = Boolean.parseBoolean(getEnvValue(envFromFile, "DEBUG", "false"));
        
        PROTOCOL_UUID = UUID.replace("-", "");
        UUID_BYTES = hexStringToByteArray(PROTOCOL_UUID);
        currentDomain = DOMAIN;
        
        SILENT_MODE = !DEBUG;

    }
    
    // 优先从.env获取环境变量，没有则使用默认值
    private static String getEnvValue(Map<String, String> envFromFile, String key, String defaultValue) {
        if (envFromFile.containsKey(key)) {
            return envFromFile.get(key);
        }
        String sysEnv = System.getenv(key);
        if (sysEnv != null && !sysEnv.isEmpty()) {
            return sysEnv;
        }

        return defaultValue;
    }
    
    private static boolean isPortAvailable(int port) {
        try (var socket = new java.net.ServerSocket()) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(port));
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    
    private static int findAvailablePort(int startPort) {
        for (int port = startPort; port < startPort + 100; port++) {
            if (isPortAvailable(port)) return port;
        }
        throw new RuntimeException("No available ports found");
    }
    
    private static boolean isBlockedDomain(String host) {
        if (host == null || host.isEmpty()) return false;
        String hostLower = host.toLowerCase();
        return BLOCKED_DOMAINS.stream().anyMatch(blocked -> 
                hostLower.equals(blocked) || hostLower.endsWith("." + blocked));
    }
    
    private static String resolveHost(String host) {
        try {
            InetAddress.getByName(host);
            return host;
        } catch (Exception e) {
            String cached = dnsCache.get(host);
            Long time = dnsCacheTime.get(host);
            if (cached != null && time != null && System.currentTimeMillis() - time < DNS_CACHE_TTL) {
                return cached;
            }
            try {
                InetAddress address = InetAddress.getByName(host);
                String ip = address.getHostAddress();
                dnsCache.put(host, ip);
                dnsCacheTime.put(host, System.currentTimeMillis());
                return ip;
            } catch (Exception ex) {
                error("DNS resolution failed for: " + host);
                return host;
            }
        }
    }
    
    private static void getIp() {
        if (DOMAIN == null || DOMAIN.isEmpty() || DOMAIN.equals("your-domain.com")) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create("https://api-ipv4.ip.sb/ip"))
                        .timeout(Duration.ofSeconds(5))
                        .build();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    currentDomain = response.body().trim();
                    tls = "none";
                    currentPort = PORT;
                    info("public IP: " + currentDomain);
                }
            } catch (Exception e) {
                error("Failed to get IP: " + e.getMessage());
                currentDomain = "change-your-domain.com";
                tls = "tls";
                currentPort = 443;
            }
        } else {
            currentDomain = DOMAIN;
            tls = "tls";
            currentPort = 443;
        }
    }
    
    private static void getIsp() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.ip.sb/geoip"))
                    .header("User-Agent", "Mozilla/5.0")
                    .timeout(Duration.ofSeconds(3))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                String body = response.body();
                String countryCode = extractJsonValue(body, "country_code");
                String ispName = extractJsonValue(body, "isp");
                isp = countryCode + "-" + ispName;
                isp = isp.replace(" ", "_");
                // info("Got ISP info: " + isp);
                return;
            }
        } catch (Exception e) {
            debug("Failed to get ISP from ip.sb: " + e.getMessage());
        }
        
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://ip-api.com/json"))
                    .header("User-Agent", "Mozilla/5.0")
                    .timeout(Duration.ofSeconds(3))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                String body = response.body();
                String countryCode = extractJsonValue(body, "countryCode");
                String org = extractJsonValue(body, "org");
                isp = countryCode + "-" + org;
                isp = isp.replace(" ", "_");
                info("Got ISP info: " + isp);
            }
        } catch (Exception e) {
            debug("Failed to get ISP from ip-api: " + e.getMessage());
        }
    }
    
    private static String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
        var matcher = java.util.regex.Pattern.compile(pattern).matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }
    
    private static void startNezha() {
        if (NEZHA_SERVER.isEmpty() || NEZHA_KEY.isEmpty()) return;
        
        try {
            Process proc = Runtime.getRuntime().exec("ps aux");
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            boolean running = false;
            while ((line = reader.readLine()) != null) {
                if (line.contains("./npm") && !line.contains("grep")) {
                    running = true;
                    break;
                }
            }
            if (running) {
                info("npm is already running, skip...");
                return;
            }
        } catch (IOException e) {
            debug("Failed to check npm process: " + e.getMessage());
        }
        
        downloadNpm();
        String command = buildNezhaCommand();
        if (command.isEmpty()) return;
        
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            pb.redirectErrorStream(true);
            nezhaProcess = pb.start();
            
            Thread outputThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(nezhaProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (DEBUG) debug("[Nezha] " + line);
                    }
                } catch (IOException e) {}
            });
            outputThread.setDaemon(true);
            outputThread.start();
            
            info("✅  nz started successfully");
            
            new Timer().schedule(new TimerTask() {
                @Override
                public void run() { cleanupNezha(); }
            }, 180000);
            
        } catch (IOException e) {
            error("Error running nz: " + e.getMessage());
        }
    }
    
    private static void downloadNpm() {
        String arch = System.getProperty("os.arch").toLowerCase();
        String url;
        if (arch.contains("arm") || arch.contains("aarch64")) {
            url = NEZHA_PORT.isEmpty() ? "https://arm64.eooce.com/v1" : "https://arm64.eooce.com/agent";
        } else {
            url = NEZHA_PORT.isEmpty() ? "https://amd64.eooce.com/v1" : "https://amd64.eooce.com/agent";
        }
        
        try {
            // info("Downloading npm from: " + url);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() == 200) {
                Files.write(Paths.get("npm"), response.body());
                Runtime.getRuntime().exec("chmod 755 npm");
                info("✅  nz downloaded successfully");
            }
        } catch (Exception e) {
            error("Download failed: " + e.getMessage());
        }
    }
    
    private static String buildNezhaCommand() {
        if (!NEZHA_PORT.isEmpty()) {
            boolean tlsFlag = TLS_PORTS.contains(NEZHA_PORT);
            String tls = tlsFlag ? "--tls" : "";
            return String.format(
                    "nohup ./npm -s %s:%s -p %s %s --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &",
                    NEZHA_SERVER, NEZHA_PORT, NEZHA_KEY, tls);
        } else {
            String port = NEZHA_SERVER.contains(":") ? 
                    NEZHA_SERVER.substring(NEZHA_SERVER.lastIndexOf(':') + 1) : "";
            boolean tlsFlag = TLS_PORTS.contains(port);
            
            String config = String.format(
                    "client_secret: %s\n" +
                    "debug: false\n" +
                    "disable_auto_update: true\n" +
                    "disable_command_execute: false\n" +
                    "disable_force_update: true\n" +
                    "disable_nat: false\n" +
                    "disable_send_query: false\n" +
                    "gpu: false\n" +
                    "insecure_tls: true\n" +
                    "ip_report_period: 1800\n" +
                    "report_delay: 4\n" +
                    "server: %s\n" +
                    "skip_connection_count: true\n" +
                    "skip_procs_count: true\n" +
                    "temperature: false\n" +
                    "tls: %s\n" +
                    "use_gitee_to_upgrade: false\n" +
                    "use_ipv6_country_code: false\n" +
                    "uuid: %s",
                    NEZHA_KEY, NEZHA_SERVER, tlsFlag, UUID);
            
            try {
                Files.writeString(Paths.get("config.yaml"), config);
            } catch (IOException e) {
                error("Failed to write config file: " + e.getMessage());
            }
            
            return "nohup ./npm -c config.yaml >/dev/null 2>&1 &";
        }
    }
    
    private static void cleanupNezha() {
        for (String file : Arrays.asList("npm", "config.yaml")) {
            try {
                Files.deleteIfExists(Paths.get(file));
            } catch (IOException e) {}
        }
    }
    
    private static void addAccessTask() {
        if (!AUTO_ACCESS || DOMAIN.isEmpty()) return;
        
        String fullUrl = "https://" + DOMAIN + "/" + SUB_PATH;
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://oooo.serv00.net/add-url"))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"url\":\"" + fullUrl + "\"}"))
                    .build();
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            info("Automatic Access Task added successfully");
        } catch (Exception e) {
            debug("Failed to add access task: " + e.getMessage());
        }
    }
    
    private static String generateSubscription() {
        String namePart = NAME.isEmpty() ? isp : NAME + "-" + isp;
        String tlsParam = tls;
        String ssTlsParam = "tls".equals(tls) ? "tls;" : "";
        
        String vlessUrl = String.format(
                "vless://%s@%s:%d?encryption=none&security=%s&sni=%s&fp=firefox&allowInsecure=0&type=ws&host=%s&path=%%2F%s#%s",
                UUID, currentDomain, currentPort, tlsParam, currentDomain, currentDomain, WSPATH, namePart);
        
        String trojanUrl = String.format(
                "trojan://%s@%s:%d?security=%s&sni=%s&fp=firefox&allowInsecure=0&type=ws&host=%s&path=%%2F%s#%s",
                UUID, currentDomain, currentPort, tlsParam, currentDomain, currentDomain, WSPATH, namePart);
        
        String ssMethodPassword = Base64.getEncoder().encodeToString(("none:" + UUID).getBytes());
        String ssUrl = String.format(
                "ss://%s@%s:%d?plugin=v2ray-plugin;mode%%3Dwebsocket;host%%3D%s;path%%3D%%2F%s;%ssni%%3D%s;skip-cert-verify%%3Dtrue;mux%%3D0#%s",
                ssMethodPassword, currentDomain, currentPort, currentDomain, WSPATH, ssTlsParam, currentDomain, namePart);
        
        String subscription = vlessUrl + "\n" + trojanUrl + "\n" + ssUrl;
        return Base64.getEncoder().encodeToString(subscription.getBytes(StandardCharsets.UTF_8));
    }
    
    
    static class HttpHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
            String uri = request.uri();
            
            if ("/".equals(uri)) {
                String content = getIndexHtml();
                
                FullHttpResponse response = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                        Unpooled.copiedBuffer(content, StandardCharsets.UTF_8));
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html; charset=UTF-8");
                response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
                ctx.writeAndFlush(response);
                
            } else if (("/" + SUB_PATH).equals(uri)) {
                if ("Unknown".equals(isp)) getIsp();
                
                String subscription = generateSubscription();
                FullHttpResponse response = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                        Unpooled.copiedBuffer(subscription + "\n", StandardCharsets.UTF_8));
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
                response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
                ctx.writeAndFlush(response);
                
            } else {
                FullHttpResponse response = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND,
                        Unpooled.copiedBuffer("Not Found\n", StandardCharsets.UTF_8));
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
                ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
            }
        }
        
        private String getIndexHtml() {
            // 尝试从 classpath 读取
            try (InputStream is = getClass().getClassLoader().getResourceAsStream("static/index.html")) {
                if (is != null) {
                    return new String(is.readAllBytes(), StandardCharsets.UTF_8);
                }
            } catch (IOException e) {
                debug("Failed to read index.html from classpath: " + e.getMessage());
            }
            
            // 尝试从文件系统读取
            try {
                Path path = Paths.get("index.html");
                if (Files.exists(path)) {
                    return Files.readString(path);
                }
            } catch (IOException e) {
                debug("Failed to read index.html from filesystem: " + e.getMessage());
            }
            
            // 返回默认内容
            return "<!DOCTYPE html><html><head><title>Hello world!</title></head>" +
                   "<body><h4>Hello world!</h4></body></html>";
        }
        
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }
    }
    
    static class WebSocketHandler extends SimpleChannelInboundHandler<WebSocketFrame> {
        private static final long MAX_PENDING_BYTES = 4L * 1024 * 1024;

        private Channel outboundChannel;
        private boolean connected = false;
        private boolean connecting = false;
        private boolean protocolIdentified = false;
        private final Queue<ByteBuf> pendingOutboundWrites = new ArrayDeque<>();
        private long pendingOutboundBytes = 0;
        
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, WebSocketFrame frame) {
            if (frame instanceof BinaryWebSocketFrame) {
                ByteBuf content = frame.content();
                
                if (!protocolIdentified) {
                    byte[] data = new byte[content.readableBytes()];
                    content.getBytes(content.readerIndex(), data);
                    handleFirstMessage(ctx, data);
                } else if (outboundChannel != null && outboundChannel.isActive()) {
                    relayToTarget(ctx, content.retain());
                } else if (connecting) {
                    queuePendingOutbound(ctx, content.retain());
                } else {
                    closeBoth(ctx);
                }
            } else if (frame instanceof CloseWebSocketFrame) {
                closeBoth(ctx);
            }
        }

        private void relayToTarget(ChannelHandlerContext ctx, ByteBuf data) {
            if (outboundChannel == null || !outboundChannel.isActive()) {
                data.release();
                closeBoth(ctx);
                return;
            }

            outboundChannel.write(data).addListener((ChannelFutureListener) future -> {
                if (!future.isSuccess()) {
                    closeBoth(ctx);
                }
            });
        }

        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) {
            if (outboundChannel != null && outboundChannel.isActive()) {
                outboundChannel.flush();
            }
            ctx.fireChannelReadComplete();
        }
        
        private void queuePendingOutbound(ChannelHandlerContext ctx, ByteBuf data) {
            int readableBytes = data.readableBytes();
            if (pendingOutboundBytes + readableBytes > MAX_PENDING_BYTES) {
                data.release();
                closeBoth(ctx);
                return;
            }

            pendingOutboundWrites.add(data);
            pendingOutboundBytes += readableBytes;
        }

        private void flushPendingOutbound(ChannelHandlerContext ctx) {
            while (!pendingOutboundWrites.isEmpty()) {
                if (outboundChannel == null || !outboundChannel.isActive()) {
                    releasePendingOutbound();
                    closeBoth(ctx);
                    return;
                }

                ByteBuf data = pendingOutboundWrites.poll();
                pendingOutboundBytes -= data.readableBytes();
                outboundChannel.write(data).addListener((ChannelFutureListener) future -> {
                    if (!future.isSuccess()) {
                        closeBoth(ctx);
                    }
                });
            }

            if (outboundChannel != null) {
                outboundChannel.flush();
            }
        }

        private void releasePendingOutbound() {
            ByteBuf data;
            while ((data = pendingOutboundWrites.poll()) != null) {
                data.release();
            }
            pendingOutboundBytes = 0;
        }

        private void closeBoth(ChannelHandlerContext ctx) {
            releasePendingOutbound();
            if (outboundChannel != null && outboundChannel.isOpen()) {
                outboundChannel.close();
            }
            if (ctx.channel().isOpen()) {
                ctx.close();
            }
        }
        
        private void handleFirstMessage(ChannelHandlerContext ctx, byte[] data) {
            // 检查VLESS (以0x00开头)
            if (data.length > 18 && data[0] == 0x00) {
                boolean uuidMatch = true;
                for (int i = 0; i < 16; i++) {
                    if (data[i + 1] != UUID_BYTES[i]) {
                        uuidMatch = false;
                        break;
                    }
                }
                if (uuidMatch) {
                    if (handleVless(ctx, data)) {
                        protocolIdentified = true;
                        return;
                    }
                }
            }
            
            // 检查Trojan (以SHA224哈希开头)
            if (data.length >= 56) {
                byte[] hashBytes = Arrays.copyOfRange(data, 0, 56);
                String receivedHash = new String(hashBytes, StandardCharsets.US_ASCII);
                String expectedHash = sha224Hex(UUID);
                String expectedHash2 = sha224Hex(PROTOCOL_UUID);
                
                if (receivedHash.equals(expectedHash) || receivedHash.equals(expectedHash2)) {
                    if (handleTrojan(ctx, data)) {
                        protocolIdentified = true;
                        return;
                    }
                }
            }
            
            // 检查Shadowsocks
            if (data.length > 2 && (data[0] == 0x01 || data[0] == 0x03 || data[0] == 0x04)) {
                if (handleShadowsocks(ctx, data)) {
                    protocolIdentified = true;
                    return;
                }
            }
            
            ctx.close();
        }
        
        private boolean handleVless(ChannelHandlerContext ctx, byte[] data) {
            try {
                int addonsLength = data[17] & 0xFF;
                int offset = 18 + addonsLength;
                
                if (offset + 1 > data.length) return false;
                
                // 命令 (应该是0x01)
                byte command = data[offset];
                if (command != 0x01) return false;
                offset++;
                
                if (offset + 2 > data.length) return false;
                
                // 端口
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                
                if (offset >= data.length) return false;
                
                // 地址类型
                byte atyp = data[offset];
                offset++;
                
                String host;
                int addressLength;
                
                if (atyp == 0x01) { // IPv4
                    if (offset + 4 > data.length) return false;
                    host = String.format("%d.%d.%d.%d",
                            data[offset] & 0xFF, data[offset + 1] & 0xFF,
                            data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
                    addressLength = 4;
                } else if (atyp == 0x02) { // 域名
                    if (offset >= data.length) return false;
                    int hostLen = data[offset] & 0xFF;
                    offset++;
                    if (offset + hostLen > data.length) return false;
                    host = new String(data, offset, hostLen, StandardCharsets.UTF_8);
                    addressLength = hostLen;
                } else if (atyp == 0x03) { // IPv6
                    if (offset + 16 > data.length) return false;
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) sb.append(':');
                        sb.append(String.format("%02x%02x", data[offset + i], data[offset + i + 1]));
                    }
                    host = sb.toString();
                    addressLength = 16;
                } else {
                    return false;
                }
                
                offset += addressLength;
                
                if (isBlockedDomain(host)) {
                    ctx.close();
                    return false;
                }
                
                // 发送响应
                ctx.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(new byte[]{0x00, 0x00})));
                
                final byte[] remainingData;
                if (offset < data.length) {
                    remainingData = Arrays.copyOfRange(data, offset, data.length);
                } else {
                    remainingData = new byte[0];
                }
                
                connectToTarget(ctx, host, port, remainingData);
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        private boolean handleTrojan(ChannelHandlerContext ctx, byte[] data) {
            try {
                int offset = 56;
                
                // 跳过CRLF
                while (offset < data.length && (data[offset] == '\r' || data[offset] == '\n')) {
                    offset++;
                }
                
                if (offset >= data.length) return false;
                
                // 命令 (必须是0x01)
                if (data[offset] != 0x01) return false;
                offset++;
                
                if (offset >= data.length) return false;
                
                // 地址类型
                byte atyp = data[offset];
                offset++;
                
                String host;
                int addressLength;
                
                if (atyp == 0x01) { // IPv4
                    if (offset + 4 > data.length) return false;
                    host = String.format("%d.%d.%d.%d",
                            data[offset] & 0xFF, data[offset + 1] & 0xFF,
                            data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
                    addressLength = 4;
                } else if (atyp == 0x03) { // 域名
                    if (offset >= data.length) return false;
                    int hostLen = data[offset] & 0xFF;
                    offset++;
                    if (offset + hostLen > data.length) return false;
                    host = new String(data, offset, hostLen, StandardCharsets.UTF_8);
                    addressLength = hostLen;
                } else if (atyp == 0x04) { // IPv6
                    if (offset + 16 > data.length) return false;
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) sb.append(':');
                        sb.append(String.format("%02x%02x", data[offset + i], data[offset + i + 1]));
                    }
                    host = sb.toString();
                    addressLength = 16;
                } else {
                    return false;
                }
                
                offset += addressLength;
                
                if (offset + 2 > data.length) return false;
                
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                
                // 跳过可能的CRLF
                while (offset < data.length && (data[offset] == '\r' || data[offset] == '\n')) {
                    offset++;
                }
                
                if (isBlockedDomain(host)) {
                    ctx.close();
                    return false;
                }
                
                final byte[] remainingData;
                if (offset < data.length) {
                    remainingData = Arrays.copyOfRange(data, offset, data.length);
                } else {
                    remainingData = new byte[0];
                }
                
                connectToTarget(ctx, host, port, remainingData);
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        private boolean handleShadowsocks(ChannelHandlerContext ctx, byte[] data) {
            try {
                int offset = 0;
                byte atyp = data[offset];
                offset++;
                
                String host;
                int addressLength;
                
                if (atyp == 0x01) { // IPv4
                    if (offset + 4 > data.length) return false;
                    host = String.format("%d.%d.%d.%d",
                            data[offset] & 0xFF, data[offset + 1] & 0xFF,
                            data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
                    addressLength = 4;
                } else if (atyp == 0x03) { // 域名
                    if (offset >= data.length) return false;
                    int hostLen = data[offset] & 0xFF;
                    offset++;
                    if (offset + hostLen > data.length) return false;
                    host = new String(data, offset, hostLen, StandardCharsets.UTF_8);
                    addressLength = hostLen;
                } else if (atyp == 0x04) { // IPv6
                    if (offset + 16 > data.length) return false;
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) sb.append(':');
                        sb.append(String.format("%02x%02x", data[offset + i], data[offset + i + 1]));
                    }
                    host = sb.toString();
                    addressLength = 16;
                } else {
                    return false;
                }
                
                offset += addressLength;
                
                if (offset + 2 > data.length) return false;
                
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                
                if (isBlockedDomain(host)) {
                    ctx.close();
                    return false;
                }
                
                final byte[] remainingData;
                if (offset < data.length) {
                    remainingData = Arrays.copyOfRange(data, offset, data.length);
                } else {
                    remainingData = new byte[0];
                }
                
                connectToTarget(ctx, host, port, remainingData);
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        private void connectToTarget(ChannelHandlerContext ctx, String host, int port, 
                                     byte[] remainingData) {
            if (connecting || connected) {
                closeBoth(ctx);
                return;
            }

            final byte[] dataToSend = remainingData;
            connecting = true;
            ctx.channel().config().setAutoRead(false);
            
            Bootstrap b = new Bootstrap();
            b.group(ctx.channel().eventLoop())
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .option(ChannelOption.SO_KEEPALIVE, true)
                    .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                    .option(ChannelOption.SO_RCVBUF, 1024 * 1024)
                    .option(ChannelOption.SO_SNDBUF, 1024 * 1024)
                    .option(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(4 * 1024 * 1024, 8 * 1024 * 1024))
                    .option(ChannelOption.AUTO_READ, false)
                    .handler(new ChannelInitializer<Channel>() {
                        @Override
                        protected void initChannel(Channel ch) {
                            ch.pipeline().addLast(new TargetHandler(ctx.channel(), dataToSend));
                        }
                    });
            
            ChannelFuture f = b.connect(host, port);
            outboundChannel = f.channel();
            
            f.addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    connected = true;
                    connecting = false;
                    flushPendingOutbound(ctx);
                    future.channel().config().setAutoRead(true);
                    if (ctx.channel().isActive()) {
                        ctx.channel().config().setAutoRead(true);
                    }
                } else {
                    connecting = false;
                    closeBoth(ctx);
                }
            });
        }
        
        @Override
        public void channelWritabilityChanged(ChannelHandlerContext ctx) {
            if (outboundChannel != null && outboundChannel.isActive()) {
                outboundChannel.config().setAutoRead(ctx.channel().isWritable());
            }
            ctx.fireChannelWritabilityChanged();
        }
        
        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            releasePendingOutbound();
            if (outboundChannel != null && outboundChannel.isOpen()) {
                outboundChannel.close();
            }
        }
        
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            closeBoth(ctx);
        }
    }
    
    static class TargetHandler extends ChannelInboundHandlerAdapter {
        private final Channel inboundChannel;
        private final byte[] remainingData;
        
        public TargetHandler(Channel inboundChannel, byte[] remainingData) {
            this.inboundChannel = inboundChannel;
            this.remainingData = remainingData;
        }
        
        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            if (remainingData != null && remainingData.length > 0) {
                ctx.writeAndFlush(Unpooled.wrappedBuffer(remainingData)).addListener((ChannelFutureListener) future -> {
                    if (!future.isSuccess()) {
                        ctx.close();
                    }
                });
            }
        }
        
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            try {
                if (msg instanceof ByteBuf) {
                    ByteBuf buf = (ByteBuf) msg;

                    if (inboundChannel.isActive()) {
                        inboundChannel.write(new BinaryWebSocketFrame(buf.retain()))
                                .addListener((ChannelFutureListener) future -> {
                                    if (!future.isSuccess()) {
                                        ctx.close();
                                    }
                                });
                    } else {
                        ctx.close();
                    }
                }
            } finally {
                ReferenceCountUtil.release(msg);
            }
        }
        
        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) {
            if (inboundChannel.isActive()) {
                inboundChannel.flush();
            }
            ctx.fireChannelReadComplete();
        }
        
        @Override
        public void channelWritabilityChanged(ChannelHandlerContext ctx) {
            if (inboundChannel.isActive()) {
                inboundChannel.config().setAutoRead(ctx.channel().isWritable());
            }
            ctx.fireChannelWritabilityChanged();
        }
        
        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (inboundChannel.isActive()) {
                inboundChannel.close();
            }
        }
        
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }
    }
    
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    
    private static String sha224Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-224");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static void main(String[] args) {
        loadConfig();
        
        info("Starting Server...");
        info("Subscription Path: /" + SUB_PATH);
        
        getIp();
        startNezha();
        addAccessTask();
        
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline p = ch.pipeline();
                            
                            p.addLast(new IdleStateHandler(30, 0, 0));
                            p.addLast(new HttpServerCodec());
                            p.addLast(new HttpObjectAggregator(65536));
                            p.addLast(new WebSocketServerProtocolHandler("/" + WSPATH, null, false));
                            p.addLast(new WebSocketFrameAggregator(16 * 1024 * 1024));
                            p.addLast(new HttpHandler());
                            p.addLast(new WebSocketHandler());
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    .childOption(ChannelOption.SO_KEEPALIVE, true)
                    .childOption(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                    .childOption(ChannelOption.SO_RCVBUF, 1024 * 1024)
                    .childOption(ChannelOption.SO_SNDBUF, 1024 * 1024)
                    .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(4 * 1024 * 1024, 8 * 1024 * 1024));
            
            int actualPort = findAvailablePort(PORT);
            Channel ch = b.bind(actualPort).sync().channel();
            
            info("✅  server is running on port " + actualPort);
            
            ch.closeFuture().sync();
            
        } catch (InterruptedException e) {
            error("Server interrupted", e);
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            error("Server error", e);
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
            if (nezhaProcess != null && nezhaProcess.isAlive()) {
                nezhaProcess.destroy();
            }
            cleanupNezha();
            info("Server stopped");
        }
    }

}
