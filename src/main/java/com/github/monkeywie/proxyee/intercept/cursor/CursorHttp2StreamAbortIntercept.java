package com.github.monkeywie.proxyee.intercept.cursor;

import com.github.monkeywie.proxyee.connect.ConnectProtoUtil;
import com.github.monkeywie.proxyee.connect.CursorProxyDebugLog;
import com.github.monkeywie.proxyee.connect.RunSseToUnifiedChatBodyConverter;
import com.github.monkeywie.proxyee.connect.SseDownstreamFormatter;
import com.github.monkeywie.proxyee.crt.CertUtil;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http2.*;
import io.netty.handler.ssl.*;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.FutureListener;
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.concurrent.Promise;

import javax.net.ssl.SSLException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Cursor HTTP/2 MITM 中转代理（独立 Netty 服务）。
 *
 * <p>客户端经 MITM 以 HTTP/1.1 访问 api2.cursor.sh；匹配到的聊天流用 HTTP/2 向上游转发：{@code Agent/RunSSE} 透传同一路径，
 * 其余多固定为 {@code /aiserver.v1.ChatService/StreamUnifiedChatWithTools}（与 {@link com.github.monkeywie.proxyee.CursorChatUtil} 中直连 Chat 一致）。
 * 若客户端 URI 为 {@code /agent.v1.AgentService/RunSSE}，则<strong>透传</strong>该 :path 与原始 Connect 请求体到上游（与 IDE 期望的 Agent 响应 protobuf 一致）。
 * 其他拦截路径（如直连 UnifiedChat）仍可将上游固定为 {@code StreamUnifiedChatWithTools}；仅当客户端误把非 Chat 体发到 Chat RPC 时才需改写（历史场景）。
 * 对 gRPC Connect 响应做<strong>解压后</strong>的终止串匹配，命中则停止后续 message、将<strong>当前帧完整</strong>下发（禁止截断 protobuf），再发 Connect 结束帧（msgType=1 空 JSON，与 {@link #CONNECT_END_STREAM_FRAME} 一致）或等价 SSE，最后在客户端 {@code LastHttpContent} flush <strong>成功</strong>后 RST 上游；{@code Agent/RunSSE} 与 UnifiedChat 均扫描。
 * <ul>
 *   <li>Agent {@code RunSSE}：上游 :path 与客户端一致；非 Agent 的拦截聊天仍可将上游固定为 {@code StreamUnifiedChatWithTools}。abort 扫描按 Connect 帧解压匹配；RunSSE 且上游 200：<strong>默认</strong>仍对客户端下发
 *   Connect 二进制分块（与 <a href="https://github.com/burpheart/cursor-tap">cursor-tap</a> 对「gRPC 请求 + 响应」按 {@code parseGRPCStream} 解析的模型一致；若响应为 SSE，其载荷仍是 Connect 帧而非 OpenAI JSON）。
 *   <strong>Agent {@code RunSSE}</strong>：即使上游 {@code Content-Type: text/event-stream}，载荷仍是 <strong>Connect 二进制分帧</strong>（借 SSE 头做无缓冲长连接），见
 *   <a href="https://github.com/burpheart/cursor-tap/blob/main/cursor-reverse-notes-1.md">cursor-tap 逆向笔记</a>；<strong>禁止</strong>转成 {@code data:} 文本 SSE。
 *   仅非 RunSSE 的拦截路径且客户端<strong>显式</strong> {@code Accept: text/event-stream} 时，才将帧格式化为标准 SSE 文本（{@link com.github.monkeywie.proxyee.connect.SseDownstreamFormatter#connectMsg0Json}）。</li>
 *   <li>其余 cursor.sh 请求 HTTP/2 透传，非 api2 域名 TCP 隧道</li>
 * </ul>
 * <p><strong>线程模型</strong>：MITM 客户端由 {@code workerGroup} 服务；到 {@code api2.cursor.sh} 的 TLS/H2 由专用 {@code upstreamEventLoopGroup}；
 * 上游 handler 内对客户端 {@link Channel} 的写经 {@link #runOnClient} 投递到客户端 I/O 线程，与上游解耦。
 */
public class CursorHttp2StreamAbortIntercept {

    private static final Logger LOG = Logger.getLogger(CursorHttp2StreamAbortIntercept.class.getName());

    /**
     * 每条上游流日志关联 id，避免多请求混在一起；不用于业务逻辑。
     */
    private static final AtomicLong CONNECT_ABORT_HANDLER_LOG_SEQ = new AtomicLong();
    private static final AtomicLong RAW_ABORT_HANDLER_LOG_SEQ = new AtomicLong();

    public static final String DEFAULT_ABORT_TOKEN = "zmgnb666";

    private static final String CURSOR_API_HOST = "api2.cursor.sh";
    private static final int CURSOR_API_PORT = 443;
    /**
     * 与 {@link com.github.monkeywie.proxyee.CursorChatUtil} 一致的上游 RPC 路径（代理与 Cursor 服务端强制使用）
     */
    private static final String FIXED_CHAT_UPSTREAM_PATH = "/aiserver.v1.ChatService/StreamUnifiedChatWithTools";
    private static final String INTERCEPT_HOST_KEYWORD = "cursor.sh";

    private static boolean hostMatchesCursor(String host) {
        return host != null && host.toLowerCase().contains(INTERCEPT_HOST_KEYWORD);
    }

    private static boolean shouldInterceptForAbort(String uri) {
        return uri.contains("StreamUnifiedChatWithTools") || uri.contains("RunSSE") || uri.contains("agent.v1.AgentService");
    }

    /**
     * 请求头是否显式要求 {@code text/event-stream}（不含「缺省」语义）。
     */
    private static boolean clientAcceptsEventStream(String acceptHeader) {
        if (acceptHeader == null || acceptHeader.isEmpty()) {
            return false;
        }
        return acceptHeader.toLowerCase().contains("text/event-stream");
    }

    /**
     * 是否对客户端下发「真·SSE 文本」（{@code data:} 行）：仅当<strong>非</strong> Agent/RunSSE 路径且客户端显式要求 event-stream。
     * Agent {@code RunSSE} 始终走 Connect 二进制（与 cursor-tap：假 SSE 真 Connect 帧 一致）。
     */
    private static boolean shouldEmitSseTextDownstream(boolean clientStartedAsRunSsePath, String acceptHeader) {
        if (clientStartedAsRunSsePath) {
            return false;
        }
        return clientAcceptsEventStream(acceptHeader);
    }

    /**
     * 将 {@link FullHttpRequest#uri()} 规范为 HTTP/2 {@code :path}（以 {@code /} 开头，可带 query）。
     * 避免部分客户端/代理把 path 写成 query 导致出现 {@code ?agent...} 等非法 :path。
     */
    private static String normalizeToHttp2Path(String uri) {
        if (uri == null || uri.isEmpty()) {
            return "/";
        }
        String s = uri.trim();
        int sp = s.indexOf(' ');
        if (sp > 0) {
            s = s.substring(0, sp);
        }
        int hash = s.indexOf('#');
        if (hash >= 0) {
            s = s.substring(0, hash);
        }
        if (s.startsWith("http://") || s.startsWith("https://")) {
            try {
                URI u = URI.create(s);
                String p = u.getRawPath();
                if (p == null || p.isEmpty()) {
                    p = "/";
                }
                String q = u.getRawQuery();
                return q != null ? p + "?" + q : p;
            } catch (Exception ignored) {
                // fall through
            }
        }
        if (s.startsWith("?")) {
            return "/" + s.substring(1);
        }
        if (!s.startsWith("/")) {
            s = "/" + s;
        }
        QueryStringDecoder dec = new QueryStringDecoder(s, false);
        String p = dec.path();
        String q = dec.rawQuery();
        if (p.isEmpty() && q != null && !q.contains("=") && q.contains("/")) {
            return "/" + q;
        }
        return q != null ? p + "?" + q : p;
    }

    /**
     * 拦截到的聊天请求：默认上游为 UnifiedChat；{@code agent.v1.AgentService/RunSSE} 必须与客户端 :path 一致，
     * 否则上游返回 Chat protobuf，而 connect-es 仍按 Agent 解码（流式异常）。
     */
    private static String resolveUpstreamPathForInterceptedChat(String clientUri) {
        String norm = normalizeToHttp2Path(clientUri);
        if (norm.contains("agent.v1.AgentService") && norm.contains("RunSSE")) {
            return norm;
        }
        return FIXED_CHAT_UPSTREAM_PATH;
    }

    @FunctionalInterface
    public interface HeaderModifier {
        void modify(HttpHeaders headers);
    }

    private final byte[] abortNeedle;
    private final HeaderModifier headerModifier;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    /**
     * 与 Cursor 上游 HTTPS/H2 专用，勿与 {@link #workerGroup} 混用。
     */
    private EventLoopGroup upstreamEventLoopGroup;
    private Channel serverChannel;

    private final AtomicReference<Channel> upstreamConnRef = new AtomicReference<>();
    private final Object upstreamConnectLock = new Object();
    /**
     * 并发请求复用同一次建连时指向同一 Future，避免多条 Bootstrap。
     */
    private volatile Future<Channel> pendingUpstreamConnect;
    private SslContext upstreamSslCtx;
    private HttpProxyServerConfig mitmConfig;

    public CursorHttp2StreamAbortIntercept() {
        this(DEFAULT_ABORT_TOKEN, null);
    }

    public CursorHttp2StreamAbortIntercept(String abortToken) {
        this(abortToken, null);
    }

    public CursorHttp2StreamAbortIntercept(String abortToken, HeaderModifier headerModifier) {
        if (abortToken == null || abortToken.isEmpty()) {
            throw new IllegalArgumentException("abortToken must not be empty");
        }
        this.abortNeedle = abortToken.getBytes(StandardCharsets.UTF_8);
        this.headerModifier = headerModifier;
    }

    public void start(int port) throws Exception {
        upstreamSslCtx = buildUpstreamSslContext();
        mitmConfig = loadMitmConfig();

        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        upstreamEventLoopGroup = new NioEventLoopGroup(1);

        ServerBootstrap b = new ServerBootstrap();
        b.group(bossGroup, workerGroup).channel(NioServerSocketChannel.class).childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                ch.pipeline().addLast("httpCodec", new HttpServerCodec()).addLast("aggregator", new HttpObjectAggregator(10 * 1024 * 1024)).addLast("proxy", new ProxyHandler());
            }
        }).childOption(ChannelOption.AUTO_READ, true);

        serverChannel = b.bind(port).sync().channel();
        LOG.info("[H2Proxy] server started on port " + port);
    }

    public void stop() {
        if (serverChannel != null) serverChannel.close();
        Channel conn = upstreamConnRef.get();
        if (conn != null && conn.isActive()) conn.close();
        if (bossGroup != null) bossGroup.shutdownGracefully();
        if (workerGroup != null) workerGroup.shutdownGracefully();
        if (upstreamEventLoopGroup != null) upstreamEventLoopGroup.shutdownGracefully();
        LOG.info("[H2Proxy] server stopped");
    }

    /**
     * 在上游线程调用亦安全：下行写固定到客户端 {@link Channel} 的 I/O 线程。
     */
    private static void runOnClient(Channel client, Runnable r) {
        EventLoop el = client.eventLoop();
        if (el.inEventLoop()) {
            r.run();
        } else {
            el.execute(r);
        }
    }

    // ======================== ProxyHandler ========================

    private class ProxyHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) throws Exception {
            logRequestHeaders(req);

            if (HttpMethod.CONNECT.equals(req.method())) {
                handleConnect(ctx, req);
                return;
            }

            String host = req.headers().get(HttpHeaderNames.HOST);
            String uri = req.uri();
            String normUri = normalizeToHttp2Path(uri);
            boolean abortIfRaw = shouldInterceptForAbort(uri);
            boolean abortIfNorm = shouldInterceptForAbort(normUri);
            boolean match = hostMatchesCursor(host) && (abortIfRaw || abortIfNorm);

            if (match) {
                LOG.info("[H2Proxy] intercepting Chat/RunSSE (abort scan): host=" + host + " uri=" + uri);
                handleChatWithAbort(ctx, req);
            } else {
                LOG.info("[H2Proxy] relay (no abort): host=" + host + " uri=" + uri);
                handleRelayViaH2(ctx, req);
            }
        }

        /**
         * CONNECT 隧道处理
         */
        private void handleConnect(ChannelHandlerContext ctx, FullHttpRequest req) {
            String hostAndPort = req.uri();
            String host = hostAndPort.contains(":") ? hostAndPort.substring(0, hostAndPort.lastIndexOf(':')) : hostAndPort;
            int port = 443;
            if (hostAndPort.contains(":")) {
                try {
                    port = Integer.parseInt(hostAndPort.substring(hostAndPort.lastIndexOf(':') + 1));
                } catch (NumberFormatException ignored) {
                }
            }

            boolean mitmApi2 = host.toLowerCase().equals(CURSOR_API_HOST);

            if (mitmApi2) {
                LOG.info("[H2Proxy] CONNECT to " + hostAndPort + " → MITM TLS");
                doMitmConnect(ctx, host);
            } else {
                LOG.info("[H2Proxy] CONNECT to " + hostAndPort + " → TCP tunnel (passthrough)");
                doTcpTunnel(ctx, host, port);
            }
        }

        /**
         * 对 api2.cursor.sh 做 MITM TLS（拆开 SSL 检查内部 HTTP 请求）
         */
        private void doMitmConnect(ChannelHandlerContext ctx, String host) {
            DefaultHttpResponse resp = new DefaultHttpResponse(HttpVersion.HTTP_1_1, new HttpResponseStatus(200, "Connection Established"));
            ctx.writeAndFlush(resp).addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) return;
                SslContext mitmSsl = buildMitmSslContext(host);
                ChannelPipeline p = ctx.pipeline();
                p.remove("aggregator");
                p.remove("httpCodec");
                p.addFirst("mitmSsl", mitmSsl.newHandler(ctx.alloc()));
                p.addAfter("mitmSsl", "httpCodec", new HttpServerCodec());
                p.addAfter("httpCodec", "aggregator", new HttpObjectAggregator(10 * 1024 * 1024));
            });
        }

        /**
         * 对非 api2 的 cursor.sh 主机，建立 TCP 隧道直接透传（不做 MITM）
         */
        private void doTcpTunnel(ChannelHandlerContext ctx, String host, int port) {
            Channel clientCh = ctx.channel();
            Bootstrap b = new Bootstrap();
            b.group(clientCh.eventLoop()).channel(NioSocketChannel.class).handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    ch.pipeline().addLast(new TunnelRelayHandler(clientCh));
                }
            });

            b.connect(host, port).addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) {
                    LOG.warning("[H2Proxy] TCP tunnel connect failed to " + host + ":" + port);
                    sendError(clientCh);
                    return;
                }
                Channel remoteCh = f.channel();
                DefaultHttpResponse resp = new DefaultHttpResponse(HttpVersion.HTTP_1_1, new HttpResponseStatus(200, "Connection Established"));
                clientCh.writeAndFlush(resp).addListener((ChannelFutureListener) wf -> {
                    if (!wf.isSuccess()) {
                        remoteCh.close();
                        return;
                    }
                    ChannelPipeline p = ctx.pipeline();
                    p.remove("aggregator");
                    p.remove("httpCodec");
                    p.remove("proxy");
                    p.addLast(new TunnelRelayHandler(remoteCh));
                });
            });
        }

        /**
         * 匹配 StreamUnifiedChat / RunSSE → HTTP/2 转发；Agent RunSSE 透传 path/body，其余拦截路径上游多为 UnifiedChat
         */
        private void handleChatWithAbort(ChannelHandlerContext ctx, FullHttpRequest req) {
            HttpHeaders forwardHeaders = req.headers().copy();
            if (headerModifier != null) {
                headerModifier.modify(forwardHeaders);
            }
            String normPath = normalizeToHttp2Path(req.uri());
            final boolean clientStartedAsRunSsePath = normPath.contains("RunSSE") || normPath.contains("agent.v1.AgentService");
            final String clientAcceptHeader = forwardHeaders.get(HttpHeaderNames.ACCEPT);
            final ByteBuf bodyCopy = RunSseToUnifiedChatBodyConverter.maybeRewriteBodyForUnifiedChat(req.content().copy(), normPath, forwardHeaders);
            HttpMethod method = req.method();
            String upstreamPath = resolveUpstreamPathForInterceptedChat(req.uri());
            boolean connectFrameAbortScan = true;

            getOrCreateUpstreamConn().addListener((GenericFutureListener<Future<Channel>>) future -> {
                if (!future.isSuccess()) {
                    bodyCopy.release();
                    sendError(ctx.channel());
                    return;
                }
                forwardViaHttp2(ctx.channel(), future.getNow(), bodyCopy, method, forwardHeaders, upstreamPath, true, connectFrameAbortScan, clientStartedAsRunSsePath, clientAcceptHeader);
            });
        }

        /**
         * 非匹配请求 → 走 HTTP/2 转发（不扫描，纯 relay）
         */
        private void handleRelayViaH2(ChannelHandlerContext ctx, FullHttpRequest req) {
            HttpHeaders forwardHeaders = req.headers().copy();
            ByteBuf bodyCopy = req.content().copy();
            HttpMethod method = req.method();
            String upstreamPath = normalizeToHttp2Path(req.uri());

            getOrCreateUpstreamConn().addListener((GenericFutureListener<Future<Channel>>) future -> {
                if (!future.isSuccess()) {
                    bodyCopy.release();
                    sendError(ctx.channel());
                    return;
                }
                forwardViaHttp2(ctx.channel(), future.getNow(), bodyCopy, method, forwardHeaders, upstreamPath, false, false, false, forwardHeaders.get(HttpHeaderNames.ACCEPT));
            });
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            LOG.log(Level.WARNING, "[H2Proxy] client channel error", cause);
            ctx.close();
        }
    }

    // ======================== TCP 隧道双向转发 ========================

    private static class TunnelRelayHandler extends ChannelInboundHandlerAdapter {
        private final Channel other;

        TunnelRelayHandler(Channel other) {
            this.other = other;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (other.isActive()) {
                other.writeAndFlush(msg);
            } else {
                if (msg instanceof io.netty.util.ReferenceCounted) {
                    ((io.netty.util.ReferenceCounted) msg).release();
                }
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (other.isActive()) other.close();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
            if (other.isActive()) other.close();
        }
    }

    // ======================== HTTP/2 转发逻辑 ========================

    /**
     * @param scanAbort             true=扫描 abort token，false=纯 relay
     * @param connectFrameAbortScan true=按 gRPC Connect 帧解压后匹配（拦截聊天路径）；false=按 HTTP/2 DATA 原始字节匹配（保留分支，当前拦截聊天恒为 true）
     */
    private void forwardViaHttp2(Channel clientChannel, Channel http2Conn, ByteBuf bodyCopy, HttpMethod method, HttpHeaders forwardHeaders, String upstreamPath, boolean scanAbort, boolean connectFrameAbortScan, boolean clientStartedAsRunSsePath, String clientAcceptHeader) {
        if (!http2Conn.isActive()) {
            bodyCopy.release();
            sendError(clientChannel);
            upstreamConnRef.set(null);
            return;
        }

        Http2StreamChannelBootstrap streamBoot = new Http2StreamChannelBootstrap(http2Conn);
        if (!scanAbort) {
            streamBoot.handler(new Http2RelayHandler(clientChannel));
        } else if (connectFrameAbortScan) {
            streamBoot.handler(new Http2ConnectFrameAbortHandler(clientChannel, abortNeedle, clientStartedAsRunSsePath, clientAcceptHeader, forwardHeaders));
        } else {
            streamBoot.handler(new Http2RawStreamAbortHandler(clientChannel, abortNeedle));
        }

        streamBoot.open().addListener((GenericFutureListener<Future<Http2StreamChannel>>) f -> {
            if (!f.isSuccess()) {
                LOG.log(Level.SEVERE, "[H2Proxy] failed to open HTTP/2 stream", f.cause());
                bodyCopy.release();
                sendError(clientChannel);
                return;
            }
            Http2StreamChannel streamChannel = f.getNow();
            Http2Headers h2Headers = buildHttp2Headers(forwardHeaders, upstreamPath, method);
            streamChannel.write(new DefaultHttp2HeadersFrame(h2Headers, false));
            int bodyBytes = bodyCopy.readableBytes();
            streamChannel.writeAndFlush(new DefaultHttp2DataFrame(bodyCopy, true));

            LOG.info("[H2Proxy] HTTP/2 stream opened, stream-id=" + streamChannel.stream().id() + " upstreamPath=" + upstreamPath + " scanAbort=" + scanAbort + " connectFrameAbort=" + connectFrameAbortScan + " bodyBytes=" + bodyBytes);
        });
    }

    private Http2Headers buildHttp2Headers(HttpHeaders httpHeaders, String upstreamPath, HttpMethod method) {
        Http2Headers h2h = new DefaultHttp2Headers();
        h2h.method(method.name());
        h2h.scheme("https");
        h2h.authority(CURSOR_API_HOST);
        h2h.path(upstreamPath);
        for (Map.Entry<String, String> entry : httpHeaders) {
            String name = entry.getKey().toLowerCase();
            if (name.equals("host") || name.equals("connection") || name.equals("keep-alive") || name.equals("transfer-encoding") || name.equals("upgrade") || name.equals("proxy-connection") || name.equals("content-length")) {
                continue;
            }
            h2h.add(name, entry.getValue());
        }
        return h2h;
    }

    // ======================== Http2ConnectFrameAbortHandler（gRPC Connect 帧解压后 abort） ========================

    /**
     * Connect 协议结束帧：告诉客户端流正常结束（不是中断）。
     * 格式：[0x02=flags(JSON,not-compressed)] [0x00000002=length] [0x7B 0x7D = "{}"]
     */
    private static final byte[] CONNECT_END_STREAM_FRAME = {0x02, 0x00, 0x00, 0x00, 0x02, 0x7B, 0x7D};

    private class Http2ConnectFrameAbortHandler extends ChannelInboundHandlerAdapter {
        private final Channel clientChannel;
        private final byte[] needle;
        /**
         * 客户端原始 URI 是否 RunSSE/Agent（与上游是 Agent 透传还是 UnifiedChat 无关，用于下行格式对照日志）。
         */
        private final boolean clientStartedAsRunSsePath;
        private final String clientAcceptHeader;
        private byte[] tail;
        private final AtomicBoolean aborted = new AtomicBoolean(false);
        private boolean clientHeadersSent = false;
        private final ConnectFrameStreamParser connectParser = new ConnectFrameStreamParser();
        /**
         * 本 handler 实例唯一 id，所有 NDJSON 行都带，便于串一条请求。
         */
        private final long streamLogId;
        /**
         * 每流最多打多少条 WIRE 明细，防止 while 循环无限刷屏。
         */
        private int wireDetailLogsEmitted;
        private static final int MAX_WIRE_DETAIL_LOGS = 50;
        /**
         * 上游 HTTP/2 DATA 分片日志条数上限（大响应会拆很多片）。
         */
        private int h2DataChunkLogCount;
        private static final int MAX_H2_DATA_LOGS = 40;
        private int dbgFrameCount;
        private long dbgBytesToClient;
        private int dbgJsonErrLogged;
        /**
         * 在多个 msgType=0 帧上扫描可抽取正文（首帧常为 bubble/元数据，见 debug S3）。
         */
        private int s3ScanMsg0Ordinal;
        private boolean s3FoundExtractableText;
        private static final int S3_MAX_MSG0_SCAN = 80;
        /**
         * RunSSE 且上游 200 且客户端 Accept 含 event-stream：下行 {@code text/event-stream}；否则透传 Connect wire
         */
        private boolean sseDownstreamActive;
        /**
         * SSE 分支：msgType=0 抽取全文的前缀差分状态
         */
        private String lastSseMsg0FullText = "";
        /**
         * 客户端原始请求头（用于下行 Connect 二进制时覆盖上游 {@code text/event-stream}，与 connect-es 期望一致）。
         */
        private final HttpHeaders clientRequestHeaders;

        Http2ConnectFrameAbortHandler(Channel clientChannel, byte[] needle, boolean clientStartedAsRunSsePath, String clientAcceptHeader, HttpHeaders clientRequestHeaders) {
            this.clientChannel = clientChannel;
            this.needle = needle;
            this.clientStartedAsRunSsePath = clientStartedAsRunSsePath;
            this.clientAcceptHeader = clientAcceptHeader;
            this.clientRequestHeaders = clientRequestHeaders;
            this.streamLogId = CONNECT_ABORT_HANDLER_LOG_SEQ.incrementAndGet();
            CursorProxyDebugLog.line("STREAM_OPEN", "Http2ConnectFrameAbortHandler", "handler_created", "{\"streamLogId\":" + streamLogId + ",\"clientChId\":" + System.identityHashCode(clientChannel) + "}");
        }

        private void runClient(Runnable r) {
            runOnClient(clientChannel, r);
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof Http2HeadersFrame) {
                Http2HeadersFrame hf = (Http2HeadersFrame) msg;
                if (!clientHeadersSent) {
                    CharSequence st = hf.headers().status();
                    int statusCode = 200;
                    try {
                        if (st != null) {
                            statusCode = Integer.parseInt(st.toString());
                        }
                    } catch (Exception ignored) {
                    }
                    boolean sseTextDownstream = shouldEmitSseTextDownstream(clientStartedAsRunSsePath, clientAcceptHeader);
                    sseDownstreamActive = statusCode == 200 && sseTextDownstream;
                    CharSequence ct = hf.headers().get(HttpHeaderNames.CONTENT_TYPE);
                    CursorProxyDebugLog.line("S1", "Http2ConnectFrameAbortHandler", "upstream_first_headers", "{\"streamLogId\":" + streamLogId + ",\"status\":\"" + CursorProxyDebugLog.esc(st != null ? st.toString() : "") + "\",\"contentType\":\"" + CursorProxyDebugLog.esc(ct != null ? ct.toString() : "") + "\",\"endStream\":" + hf.isEndStream() + ",\"clientStartedAsRunSsePath\":" + clientStartedAsRunSsePath + ",\"clientAccept\":\"" + CursorProxyDebugLog.esc(clientAcceptHeader) + "\",\"sseTextDownstream\":" + sseTextDownstream + ",\"sseDownstreamActive\":" + sseDownstreamActive + "}");
                    CursorProxyDebugLog.line("S1_H", "Http2ConnectFrameAbortHandler", "downstream_format", "{\"streamLogId\":" + streamLogId + ",\"mode\":\"" + (sseDownstreamActive ? "sse_connectMsg0_json_text_event_stream" : "connect_binary_chunked") + "\"}");
                    final boolean endStream = hf.isEndStream();
                    runClient(() -> {
                        if (sseDownstreamActive) {
                            writeSseStreamResponseHeaders(clientChannel, streamLogId);
                        } else {
                            writeClientConnectWireResponseHeaders(clientChannel, hf.headers(), clientRequestHeaders, streamLogId, clientStartedAsRunSsePath);
                        }
                        clientHeadersSent = true;
                        if (endStream) {
                            finishClient();
                        }
                    });
                } else if (hf.isEndStream()) {
                    runClient(this::finishClient);
                }
                return;
            }
            if (msg instanceof Http2DataFrame) {
                Http2DataFrame df = (Http2DataFrame) msg;
                boolean endStream = df.isEndStream();
                if (aborted.get()) {
                    df.release();
                    return;
                }

                ByteBuf buf = df.content();
                int n = buf.readableBytes();
                if (n > 0) {
                    // #region agent log - 上游数据块详细日志
                    byte[] bufCopy = new byte[Math.min(n, 64)];
                    buf.getBytes(buf.readerIndex(), bufCopy);
                    String bufHexPrefix = CursorProxyDebugLog.hexPrefix(bufCopy, bufCopy.length);
                    if (h2DataChunkLogCount < MAX_H2_DATA_LOGS) {
                        h2DataChunkLogCount++;
                        CursorProxyDebugLog.line("H2_DATA", "Http2ConnectFrameAbortHandler", "upstream_data_chunk",
                                "{\"streamLogId\":" + streamLogId + ",\"chunkBytes\":" + n
                                        + ",\"endStream\":" + endStream + ",\"seq\":" + h2DataChunkLogCount
                                        + ",\"bufHexPrefix\":\"" + bufHexPrefix + "\""
                                        + ",\"parserRemainingBefore\":" + connectParser.remaining() + "}");
                    } else if (h2DataChunkLogCount == MAX_H2_DATA_LOGS) {
                        CursorProxyDebugLog.line("H2_DATA_CAP", "Http2ConnectFrameAbortHandler", "upstream_data_capped",
                                "{\"streamLogId\":" + streamLogId + ",\"maxLogs\":" + MAX_H2_DATA_LOGS + "}");
                        h2DataChunkLogCount++;
                    }
                    // #endregion
                    connectParser.append(buf);
                }
                df.release();

                try {
                    processBufferedFrames(ctx);
                } catch (IllegalStateException e) {
                    LOG.log(Level.WARNING, "[H2Proxy] invalid Connect frame stream", e);
                    abortWithError(ctx);
                    return;
                }

                if (endStream) {
                    if (!aborted.get() && connectParser.hasIncompleteTrailingData()) {
                        LOG.warning("[H2Proxy] upstream endStream with incomplete Connect frame in buffer, len=" + connectParser.remaining());
                    }
                    runClient(this::finishClient);
                }
                return;
            }
            if (msg instanceof io.netty.util.ReferenceCounted) {
                ((io.netty.util.ReferenceCounted) msg).release();
            }
        }

        /**
         * 按完整 Connect 帧处理：先解压 protobuf 帧载荷并做 needle 匹配，再决定是否转发整帧 wire 字节。
         */
        private void processBufferedFrames(ChannelHandlerContext ctx) {
            while (true) {
                byte[] wire = connectParser.pollWireFrame();
                if (wire == null) {
                    break;
                }

                ConnectFrameStreamParser.ParsedConnectFrame p = ConnectFrameStreamParser.ParsedConnectFrame.parse(wire);

                // #region agent log - 详细帧解析日志
                String wireHexPrefix = CursorProxyDebugLog.hexPrefix(wire, 32);
                String payloadHexPrefix = p.payloadDecompressed == null ? "null" : CursorProxyDebugLog.hexPrefix(p.payloadDecompressed, 48);
                CursorProxyDebugLog.line("FRAME", "Http2ConnectFrameAbortHandler", "frame_parsed",
                        "{\"streamLogId\":" + streamLogId + ",\"msgType\":" + p.messageType
                                + ",\"wireLen\":" + wire.length
                                + ",\"wireHexPrefix\":\"" + wireHexPrefix + "\""
                                + ",\"payloadDecompressedNull\":" + (p.payloadDecompressed == null)
                                + ",\"payloadLen\":" + (p.payloadDecompressed == null ? -1 : p.payloadDecompressed.length)
                                + ",\"payloadHexPrefix\":\"" + payloadHexPrefix + "\""
                                + ",\"tailLen\":" + (tail == null ? 0 : tail.length)
                                + ",\"aborted\":" + aborted.get() + "}");
                // #endregion

                // 如果已经 abort，不再处理新帧
                if (aborted.get()) {
                    break;
                }

                if (p.messageType == 0 && p.payloadDecompressed != null) {
                    // #region agent log - 检查 abort 匹配前的状态
                    boolean hasNeedle = CursorStreamAbortIntercept.containsAbortPattern(tail, p.payloadDecompressed, needle);
                    String payloadTextPreview = new String(p.payloadDecompressed, StandardCharsets.UTF_8);
                    if (payloadTextPreview.length() > 200) {
                        payloadTextPreview = payloadTextPreview.substring(0, 200) + "...";
                    }
                    payloadTextPreview = payloadTextPreview.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
                    CursorProxyDebugLog.line("MATCH_CHECK", "Http2ConnectFrameAbortHandler", "before_abort_check",
                            "{\"streamLogId\":" + streamLogId + ",\"hasNeedle\":" + hasNeedle
                                    + ",\"needleStr\":\"" + new String(needle, StandardCharsets.UTF_8).replace("\\", "\\\\").replace("\"", "\\\"") + "\""
                                    + ",\"payloadTextPreview\":\"" + payloadTextPreview + "\"" + "}");
                    // #endregion

                    if (hasNeedle) {
                        // 与 containsAbortPattern 一致：在 tail+payload 上定位，再映射到本帧 payload 字节偏移
                        int glueIdx = CursorStreamAbortIntercept.findAbortNeedleStartIndex(tail, p.payloadDecompressed, needle);
                        int pl = tail == null ? 0 : tail.length;
                        int tokenByteIdx = -1;
                        if (glueIdx >= 0) {
                            tokenByteIdx = glueIdx < pl ? 0 : glueIdx - pl;
                        }
                        if (tokenByteIdx < 0) {
                            tokenByteIdx = CursorStreamAbortIntercept.findAbortNeedleStartIndex(null, p.payloadDecompressed, needle);
                        }
                        // needle 前字节：在 tail+payload 上取 [0, glueIdx)，避免 token 落在 tail 重叠区时误用空 prefix
                        byte[] prefixBeforeNeedle;
                        if (glueIdx >= 0) {
                            if (glueIdx <= pl) {
                                prefixBeforeNeedle = (tail == null || glueIdx == 0)
                                        ? new byte[0]
                                        : Arrays.copyOfRange(tail, 0, glueIdx);
                            } else {
                                prefixBeforeNeedle = Arrays.copyOfRange(p.payloadDecompressed, 0, glueIdx - pl);
                            }
                        } else if (tokenByteIdx > 0) {
                            prefixBeforeNeedle = Arrays.copyOfRange(p.payloadDecompressed, 0, tokenByteIdx);
                        } else {
                            prefixBeforeNeedle = new byte[0];
                        }
                        boolean lastRoleIsAssistant = ConnectProtoUtil.lastRoleBeforeNeedleIsAssistant(prefixBeforeNeedle);
                        // #region agent log
                        CursorProxyDebugLog.line("ABORT_ROLE", "Http2ConnectFrameAbortHandler", "role_gate",
                                "{\"streamLogId\":" + streamLogId + ",\"glueIdx\":" + glueIdx + ",\"pl\":" + pl
                                        + ",\"tokenByteIdx\":" + tokenByteIdx + ",\"lastRoleIsAssistant\":" + lastRoleIsAssistant + "}");
                        // #endregion
                        if (!lastRoleIsAssistant) {
                            CursorProxyDebugLog.line("ABORT_FP", "Http2ConnectFrameAbortHandler", "skip_false_positive",
                                    "{\"streamLogId\":" + streamLogId + ",\"reason\":\"needle_in_user_or_system_or_no_assistant_before_needle\"}");
                        } else {
                        aborted.set(true);
                        LOG.info("[H2Proxy] abort token matched (decompressed protobuf payload), wireLen=" + wire.length);

                        // #region agent log - 详细的 token 定位和截断过程
                        CursorProxyDebugLog.line("ABORT_HIT", "Http2ConnectFrameAbortHandler", "token_match_details",
                                "{\"streamLogId\":" + streamLogId + ",\"glueIdx\":" + glueIdx + ",\"pl\":" + pl
                                        + ",\"tokenByteIdx\":" + tokenByteIdx
                                        + ",\"payloadLen\":" + p.payloadDecompressed.length + ",\"wireLen\":" + wire.length
                                        + ",\"sseDownstreamActive\":" + sseDownstreamActive + ",\"msgType\":" + p.messageType + "}");
                        // #endregion

                        if (tokenByteIdx > 0) {
                            // 使用 removeAbortTokenFromWire - 它会正确处理嵌套protobuf字段长度
                            byte[] newWire = ConnectProtoUtil.removeAbortTokenFromWire(wire, needle);
                            
                            // 获取截断后的payload用于日志（从wire解压）
                            byte[] cleanPayload = newWire == null ? null : ConnectProtoUtil.extractPayloadFromWire(newWire);

                            // 原始payload和截断后payload的详细对比
                            String originalPayloadHex = CursorProxyDebugLog.hexPrefix(p.payloadDecompressed, 64);
                            String cleanPayloadHex = cleanPayload == null ? "null" : CursorProxyDebugLog.hexPrefix(cleanPayload, 64);
                            String newWireHex = newWire == null ? "null" : CursorProxyDebugLog.hexPrefix(newWire, 48);

                            // token前后各50字节的上下文
                            int ctxStart = Math.max(0, tokenByteIdx - 50);
                            int ctxEnd = Math.min(p.payloadDecompressed.length, tokenByteIdx + 50 + needle.length);
                            byte[] contextAroundToken = Arrays.copyOfRange(p.payloadDecompressed, ctxStart, ctxEnd);
                            String contextHex = CursorProxyDebugLog.hexPrefix(contextAroundToken, contextAroundToken.length);
                            String contextStr = new String(contextAroundToken, StandardCharsets.UTF_8)
                                    .replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");

                            // 测试：提取完整payload和截断后payload的文本，对比可解析性
                            String fullText = ConnectProtoUtil.extractTextFromResponseLenient(p.payloadDecompressed);
                            String cleanPayloadText = cleanPayload == null ? null : ConnectProtoUtil.extractTextFromResponseLenient(cleanPayload);
                            String fullTextPreview = fullText == null ? "null" : (fullText.length() > 100 ? fullText.substring(0, 100).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") : fullText.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n"));
                            String cleanPayloadTextPreview = cleanPayloadText == null ? "null" : (cleanPayloadText.length() > 100 ? cleanPayloadText.substring(0, 100).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") : cleanPayloadText.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n"));

                            // #region agent log
                            CursorProxyDebugLog.line("ABORT_TRUNC", "Http2ConnectFrameAbortHandler", "truncate_result",
                                    "{\"streamLogId\":" + streamLogId + ",\"originalPayloadLen\":" + p.payloadDecompressed.length
                                            + ",\"originalPayloadHex\":\"" + originalPayloadHex + "\""
                                            + ",\"tokenByteIdx\":" + tokenByteIdx 
                                            + ",\"cleanPayloadLen\":" + (cleanPayload == null ? -1 : cleanPayload.length)
                                            + ",\"cleanPayloadHex\":\"" + cleanPayloadHex + "\""
                                            + ",\"contextAroundTokenHex\":\"" + contextHex + "\""
                                            + ",\"contextStr\":\"" + contextStr + "\""
                                            + ",\"fullTextExtractable\":" + (fullText != null) + ",\"fullTextPreview\":\"" + fullTextPreview + "\""
                                            + ",\"cleanPayloadTextExtractable\":" + (cleanPayloadText != null) + ",\"cleanPayloadTextPreview\":\"" + cleanPayloadTextPreview + "\""
                                            + ",\"newWireNull\":" + (newWire == null)
                                            + ",\"newWireLen\":" + (newWire == null ? -1 : newWire.length)
                                            + ",\"newWireHex\":\"" + newWireHex + "\"}");
                            // #endregion

                            runClient(() -> {
                                ChannelFuture f;
                                if (sseDownstreamActive) {
                                    // SSE分支：转换为文本格式
                                    String sseCleanText = new String(cleanPayload, StandardCharsets.UTF_8);
                                    String json = SseDownstreamFormatter.connectMsg0Json(sseCleanText);
                                    ByteBuf buf = SseDownstreamFormatter.sseDataLineUtf8(json);
                                    // #region agent log
                                    CursorProxyDebugLog.line("WRITE", "Http2ConnectFrameAbortHandler", "sse_write",
                                            "{\"streamLogId\":" + streamLogId + ",\"jsonLen\":" + json.length()
                                                    + ",\"bufLen\":" + buf.readableBytes() + "}");
                                    // #endregion
                                    f = clientChannel.writeAndFlush(new DefaultHttpContent(buf));
                                } else {
                                    // Connect二进制分支：发送清理后的帧
                                    ByteBuf buf = Unpooled.wrappedBuffer(newWire);
                                    // #region agent log
                                    CursorProxyDebugLog.line("WRITE", "Http2ConnectFrameAbortHandler", "connect_write",
                                            "{\"streamLogId\":" + streamLogId + ",\"newWireLen\":" + newWire.length
                                                    + ",\"bufLen\":" + buf.readableBytes()
                                                    + ",\"clientActive\":" + clientChannel.isActive()
                                                    + ",\"clientWritable\":" + clientChannel.isWritable() + "}");
                                    // #endregion
                                    f = clientChannel.writeAndFlush(new DefaultHttpContent(buf));
                                }
                                f.addListener(done -> {
                                    // #region agent log
                                    Throwable cause = done.cause();
                                    String errMsg = cause == null ? "" : cause.getClass().getSimpleName() + ":" + cause.getMessage();
                                    CursorProxyDebugLog.line("ABORT_FLUSH", "Http2ConnectFrameAbortHandler", "first_frame_flush",
                                            "{\"streamLogId\":" + streamLogId + ",\"success\":" + done.isSuccess()
                                                    + ",\"clientActive\":" + clientChannel.isActive()
                                                    + ",\"error\":\"" + errMsg.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}");
                                    // #endregion
                                });
                            });
                        } else {
                            // needle 在 payload 起点或仅落在 tail：本帧不发正文（勿再下发含 token 的完整 wire）
                            byte[] emptyWire = ConnectProtoUtil.recompressToConnectWire(wire, new byte[0]);
                            final byte[] toSend = emptyWire != null ? emptyWire : wire;

                            // #region agent log
                            CursorProxyDebugLog.line("ABORT_EMPTY", "Http2ConnectFrameAbortHandler", "empty_payload",
                                    "{\"streamLogId\":" + streamLogId + ",\"emptyWireNull\":" + (emptyWire == null)
                                            + ",\"toSendLen\":" + toSend.length
                                            + ",\"fallbackToRawWire\":" + (emptyWire == null) + "}");
                            // #endregion

                            runClient(() -> {
                                ChannelFuture f;
                                if (sseDownstreamActive) {
                                    String json = SseDownstreamFormatter.connectMsg0Json("");
                                    ByteBuf buf = SseDownstreamFormatter.sseDataLineUtf8(json);
                                    f = clientChannel.writeAndFlush(new DefaultHttpContent(buf));
                                } else {
                                    ByteBuf buf = Unpooled.wrappedBuffer(toSend);
                                    // #region agent log
                                    CursorProxyDebugLog.line("WRITE", "Http2ConnectFrameAbortHandler", "empty_write",
                                            "{\"streamLogId\":" + streamLogId + ",\"toSendLen\":" + toSend.length
                                                    + ",\"clientActive\":" + clientChannel.isActive() + "}");
                                    // #endregion
                                    f = clientChannel.writeAndFlush(new DefaultHttpContent(buf));
                                }
                                f.addListener(done -> {
                                    // #region agent log
                                    CursorProxyDebugLog.line("ABORT_FLUSH", "Http2ConnectFrameAbortHandler", "empty_frame_flush",
                                            "{\"streamLogId\":" + streamLogId + ",\"success\":" + done.isSuccess() + "}");
                                    // #endregion
                                });
                            });
                        }

                        // 立即结束流 - 添加日志确认时序
                        // #region agent log
                        CursorProxyDebugLog.line("ABORT_TIMING", "Http2ConnectFrameAbortHandler", "calling_end_close",
                                "{\"streamLogId\":" + streamLogId + ",\"note\":\"about_to_call_flushClientAbortEndAndClose\"}");
                        // #endregion
                        flushClientAbortEndAndClose(ctx);
                        return;
                        }
                    }

                    tail = CursorStreamAbortIntercept.suffixForOverlap(p.payloadDecompressed, needle.length);
                }

                // ✅ 正常转发帧
                // 测试：提取文本作为基线
                String relayText = null;
                if (p.messageType == 0 && p.payloadDecompressed != null) {
                    relayText = ConnectProtoUtil.extractTextFromResponseLenient(p.payloadDecompressed);
                }
                String relayTextPreview = relayText == null ? "null" : (relayText.length() > 80 ? relayText.substring(0, 80).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") : relayText.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n"));

                // #region agent log - 正常转发日志
                CursorProxyDebugLog.line("RELAY", "Http2ConnectFrameAbortHandler", "normal_relay",
                        "{\"streamLogId\":" + streamLogId + ",\"msgType\":" + p.messageType
                                + ",\"wireLen\":" + wire.length
                                + ",\"sseDownstreamActive\":" + sseDownstreamActive
                                + ",\"clientActive\":" + clientChannel.isActive()
                                + ",\"clientWritable\":" + clientChannel.isWritable()
                                + ",\"relayTextExtractable\":" + (relayText != null)
                                + ",\"relayTextPreview\":\"" + relayTextPreview + "\"}");
                // #endregion
                runClient(() -> {
                    ChannelFuture f;
                    if (sseDownstreamActive) {
                        f = writeSseFromConnectFrame(p, wire, false);
                    } else {
                        ByteBuf buf = Unpooled.wrappedBuffer(wire);
                        // #region agent log
                        CursorProxyDebugLog.line("RELAY_WRITE", "Http2ConnectFrameAbortHandler", "writing_normal_frame",
                                "{\"streamLogId\":" + streamLogId + ",\"wireLen\":" + wire.length
                                        + ",\"bufLen\":" + buf.readableBytes()
                                        + ",\"clientActive\":" + clientChannel.isActive()
                                        + ",\"clientWritable\":" + clientChannel.isWritable() + "}");
                        // #endregion
                        f = clientChannel.writeAndFlush(new DefaultHttpContent(buf));
                    }
                    if (f != null) {
                        f.addListener(done -> {
                            // #region agent log
                            Throwable cause = done.cause();
                            String errMsg = cause == null ? "" : cause.getClass().getSimpleName() + ":" + cause.getMessage();
                            CursorProxyDebugLog.line("RELAY_FLUSH", "Http2ConnectFrameAbortHandler", "normal_frame_flush",
                                    "{\"streamLogId\":" + streamLogId + ",\"success\":" + done.isSuccess()
                                            + ",\"clientActive\":" + clientChannel.isActive()
                                            + ",\"error\":\"" + errMsg.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}");
                            // #endregion
                        });
                    }
                });
            }
        }

        /**
         * @param deferFlush true=仅 {@link Channel#write}，与随后 {@link #flushClientAbortEndAndClose(ChannelHandlerContext)} 一次 flush，避免多帧与尾包之间客户端先断开
         * @return 最后一次写操作的 future；若本帧未向客户端写出内容（例如 msg0 且 delta 为空）则返回 null
         */
        private ChannelFuture writeSseFromConnectFrame(ConnectFrameStreamParser.ParsedConnectFrame p, byte[] wire, boolean deferFlush) {
            if (p.messageType == 1 && p.payloadDecompressed != null) {
                ByteBuf buf = SseDownstreamFormatter.connectMsg1JsonPayload(p.payloadDecompressed);
                dbgBytesToClient += buf.readableBytes();
                return deferFlush ? clientChannel.write(new DefaultHttpContent(buf)) : clientChannel.writeAndFlush(new DefaultHttpContent(buf));
            }
            if (p.messageType == 0 && p.payloadDecompressed != null) {
                String t = ConnectProtoUtil.extractTextFromResponseLenient(p.payloadDecompressed);
                if (t == null) {
                    t = "";
                }
                String delta = computeMsg0TextDelta(lastSseMsg0FullText, t);
                lastSseMsg0FullText = t;
                if (delta.isEmpty()) {
                    if (p.payloadDecompressed.length == 0) {
                        return null;
                    }
                    if (dbgBytesToClient == 0) {
                        String json = SseDownstreamFormatter.connectFallbackJson(p.messageType, wire);
                        ByteBuf buf = SseDownstreamFormatter.sseDataLineUtf8(json);
                        dbgBytesToClient += buf.readableBytes();
                        return deferFlush ? clientChannel.write(new DefaultHttpContent(buf)) : clientChannel.writeAndFlush(new DefaultHttpContent(buf));
                    }
                    return null;
                }
                String json = SseDownstreamFormatter.connectMsg0Json(delta);
                ByteBuf buf = SseDownstreamFormatter.sseDataLineUtf8(json);
                dbgBytesToClient += buf.readableBytes();
                return deferFlush ? clientChannel.write(new DefaultHttpContent(buf)) : clientChannel.writeAndFlush(new DefaultHttpContent(buf));
            }
            String json = SseDownstreamFormatter.connectFallbackJson(p.messageType, wire);
            ByteBuf buf = SseDownstreamFormatter.sseDataLineUtf8(json);
            dbgBytesToClient += buf.readableBytes();
            return deferFlush ? clientChannel.write(new DefaultHttpContent(buf)) : clientChannel.writeAndFlush(new DefaultHttpContent(buf));
        }

        private String computeMsg0TextDelta(String previousFull, String currentFull) {
            if (currentFull == null || currentFull.isEmpty()) {
                return "";
            }
            if (previousFull == null || previousFull.isEmpty()) {
                return currentFull;
            }
            if (currentFull.startsWith(previousFull)) {
                return currentFull.substring(previousFull.length());
            }
            if (previousFull.startsWith(currentFull)) {
                return "";
            }
            return currentFull;
        }

        /**
         * 对上游 HTTP/2 流发 RST 并关闭该流；{@link #aborted} 须已由调用方置位。
         */
        private void rstUpstreamStream(ChannelHandlerContext ctx) {
            CursorProxyDebugLog.line("RST_UPSTREAM", "rstUpstreamStream", "rst_cancel", "{\"streamLogId\":" + streamLogId + ",\"upstreamChId\":" + System.identityHashCode(ctx.channel()) + "}");
            ctx.channel().writeAndFlush(new DefaultHttp2ResetFrame(Http2Error.CANCEL)).addListener(ChannelFutureListener.CLOSE);
        }

        /**
         * 向客户端写 Connect 结束帧（或 SSE 尾），再关闭与客户端的连接；在 {@link LastHttpContent} flush 完成后再对上游 RST，避免与下行竞态（H3）。
         * abort 路径上命中帧的完整 body 应先 {@link Channel#write} 入队（不单独 flush），再写 END/SSE 尾，最后 {@code writeAndFlush(LastHttpContent)} 一次刷出；
         * 仅当 LastHttpContent 刷出<strong>成功</strong>后才 {@link #rstUpstreamStream}。
         *
         * @param upstreamCtx 上游 HTTP/2 流 handler 上下文，供 {@link #rstUpstreamStream} 使用
         */
        private void flushClientAbortEndAndClose(ChannelHandlerContext upstreamCtx) {
            // #region agent log
            CursorProxyDebugLog.line("ABORT_TIMING", "Http2ConnectFrameAbortHandler", "scheduling_end_close",
                    "{\"streamLogId\":" + streamLogId + ",\"clientActive\":" + clientChannel.isActive()
                            + ",\"note\":\"scheduling_flushClientAbortEndAndCloseOnClient_via_runClient\"}");
            // #endregion
            runClient(() -> flushClientAbortEndAndCloseOnClient(upstreamCtx));
        }

        private void flushClientAbortEndAndCloseOnClient(ChannelHandlerContext upstreamCtx) {
            // #region agent log
            String connectEndFrameHex = CursorProxyDebugLog.hexPrefix(CONNECT_END_STREAM_FRAME, CONNECT_END_STREAM_FRAME.length);
            CursorProxyDebugLog.line("ABORT_TIMING", "Http2ConnectFrameAbortHandler", "inside_end_close_lambda",
                    "{\"streamLogId\":" + streamLogId + ",\"thread\":\"" + Thread.currentThread().getName().replace("\\", "\\\\").replace("\"", "\\\"") + "\"" + ",\"clientActive\":" + clientChannel.isActive() + "}");
            CursorProxyDebugLog.line("ABORT_END", "Http2ConnectFrameAbortHandler", "sending_end_frames",
                    "{\"streamLogId\":" + streamLogId + ",\"sseDownstreamActive\":" + sseDownstreamActive
                            + ",\"clientActiveBefore\":" + clientChannel.isActive()
                            + ",\"clientWritableBefore\":" + clientChannel.isWritable()
                            + ",\"connectEndFrameHex\":\"" + connectEndFrameHex + "\"}");
            // #endregion

            if (sseDownstreamActive) {
                // SSE 模式：发送 [DONE] 事件
                ByteBuf done = SseDownstreamFormatter.sseDoneLine();
                String doneStr = done.toString(StandardCharsets.UTF_8).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
                // #region agent log
                CursorProxyDebugLog.line("END_SSE", "Http2ConnectFrameAbortHandler", "sse_done_line",
                        "{\"streamLogId\":" + streamLogId + ",\"doneLine\":\"" + doneStr + "\"}");
                // #endregion
                clientChannel.write(new DefaultHttpContent(done));

                // 发送空行表示 SSE 流结束
                ByteBuf emptyLine = Unpooled.copiedBuffer("\n", StandardCharsets.UTF_8);
                clientChannel.write(new DefaultHttpContent(emptyLine));
            } else {
                // Connect 模式：发送结束帧
                // #region agent log
                CursorProxyDebugLog.line("END_CONNECT", "Http2ConnectFrameAbortHandler", "connect_end_frame",
                        "{\"streamLogId\":" + streamLogId + ",\"endFrameLen\":" + CONNECT_END_STREAM_FRAME.length + "}");
                // #endregion
                clientChannel.write(new DefaultHttpContent(Unpooled.wrappedBuffer(CONNECT_END_STREAM_FRAME)));
            }

            ChannelFuture lastFut = clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);

            lastFut.addListener(f -> {
                // #region agent log
                Throwable cause = f.cause();
                String errMsg = cause == null ? "" : cause.getClass().getSimpleName() + ":" + cause.getMessage();
                CursorProxyDebugLog.line("ABORT_LAST", "Http2ConnectFrameAbortHandler", "last_content_flush",
                        "{\"streamLogId\":" + streamLogId + ",\"success\":" + f.isSuccess()
                                + ",\"clientActive\":" + clientChannel.isActive()
                                + ",\"error\":\"" + errMsg.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}");
                // #endregion
                if (f.isSuccess()) {
                    // 等客户端完全收到数据后再 RST 上游
                    rstUpstreamStream(upstreamCtx);
                }
            });
            lastFut.addListener(ChannelFutureListener.CLOSE);
        }

        private void abortWithError(ChannelHandlerContext ctx) {
            CursorProxyDebugLog.line("ABORT_ERR", "Http2ConnectFrameAbortHandler", "abort_with_error", "{\"streamLogId\":" + streamLogId + ",\"clientActive\":" + clientChannel.isActive() + "}");
            if (!aborted.getAndSet(true)) {
                runClient(() -> clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT).addListener(ChannelFutureListener.CLOSE));
            }
            ctx.close();
        }

        private void finishClient() {
            if (aborted.get()) {
                return;
            }
            CursorProxyDebugLog.line("FINISH", "Http2ConnectFrameAbortHandler", "normal_stream_end", "{\"streamLogId\":" + streamLogId + ",\"framesToClient\":" + dbgFrameCount + ",\"bytesToClient\":" + dbgBytesToClient + ",\"parserRemaining\":" + connectParser.remaining() + "}");
            if (clientStartedAsRunSsePath && !s3FoundExtractableText && s3ScanMsg0Ordinal > 0) {
                CursorProxyDebugLog.line("S3_MISS", "Http2ConnectFrameAbortHandler", "no_text_in_msg0_scan", "{\"msg0FramesScanned\":" + s3ScanMsg0Ordinal + ",\"note\":\"extractTextFromResponse null on all scanned msg0 payloads; " + "schema may differ or text in other fields\"}");
            }
            if (sseDownstreamActive && !aborted.get()) {
                ByteBuf doneBuf = SseDownstreamFormatter.sseDoneLine();
                dbgBytesToClient += doneBuf.readableBytes();
                clientChannel.write(new DefaultHttpContent(doneBuf));
            }
            clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT).addListener(ChannelFutureListener.CLOSE);
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            CursorProxyDebugLog.line("H2_UP_INACTIVE", "Http2ConnectFrameAbortHandler", "upstream_inactive", "{\"streamLogId\":" + streamLogId + ",\"aborted\":" + aborted.get() + "}");
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            LOG.log(Level.WARNING, "[H2Proxy] Chat/Connect frame stream error", cause);
            CursorProxyDebugLog.line("EX_H2", "Http2ConnectFrameAbortHandler", "exception", "{\"streamLogId\":" + streamLogId + ",\"type\":\"" + CursorProxyDebugLog.esc(cause.getClass().getSimpleName()) + "\",\"msg\":\"" + CursorProxyDebugLog.esc(cause.getMessage()) + "\"}");
            if (!aborted.getAndSet(true)) {
                runClient(() -> clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT).addListener(ChannelFutureListener.CLOSE));
            }
            ctx.close();
        }
    }

    /**
     * RunSSE 等：上游响应可能为 SSE 文本或非 Connect 封装，按 HTTP/2 DATA 原始字节做 needle 匹配（先匹配再转发）。
     */
    private class Http2RawStreamAbortHandler extends ChannelInboundHandlerAdapter {
        private final Channel clientChannel;
        private final byte[] needle;
        private final long rawStreamLogId;
        private byte[] tail;
        private final AtomicBoolean aborted = new AtomicBoolean(false);
        private boolean clientHeadersSent = false;

        Http2RawStreamAbortHandler(Channel clientChannel, byte[] needle) {
            this.clientChannel = clientChannel;
            this.needle = needle;
            this.rawStreamLogId = RAW_ABORT_HANDLER_LOG_SEQ.incrementAndGet();
            CursorProxyDebugLog.line("RAW_OPEN", "Http2RawStreamAbortHandler", "handler_created", "{\"rawStreamLogId\":" + rawStreamLogId + "}");
        }

        private void runClient(Runnable r) {
            runOnClient(clientChannel, r);
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof Http2HeadersFrame) {
                Http2HeadersFrame hf = (Http2HeadersFrame) msg;
                if (!clientHeadersSent) {
                    runClient(() -> {
                        writeClientResponseHeaders(clientChannel, hf.headers(), true);
                        clientHeadersSent = true;
                        if (hf.isEndStream()) {
                            finishClient();
                        }
                    });
                } else if (hf.isEndStream()) {
                    runClient(this::finishClient);
                }
                return;
            }
            if (msg instanceof Http2DataFrame) {
                Http2DataFrame df = (Http2DataFrame) msg;
                boolean endStream = df.isEndStream();
                if (aborted.get()) {
                    df.release();
                    return;
                }

                ByteBuf buf = df.content();
                int n = buf.readableBytes();
                if (n == 0) {
                    df.release();
                    if (endStream) {
                        runClient(this::finishClient);
                    }
                    return;
                }

                byte[] chunk = new byte[n];
                buf.getBytes(buf.readerIndex(), chunk);
                df.release();

                if (CursorStreamAbortIntercept.containsAbortPattern(tail, chunk, needle)) {
                    int needleStart = CursorStreamAbortIntercept.findAbortNeedleStartIndex(tail, chunk, needle);
                    int pl = tail == null ? 0 : tail.length;
                    int keepLen = needleStart >= 0 ? needleStart - pl : 0;
                    aborted.set(true);
                    ctx.channel().writeAndFlush(new DefaultHttp2ResetFrame(Http2Error.CANCEL)).addListener(ChannelFutureListener.CLOSE);
                    CursorProxyDebugLog.line("RAW_ABORT", "Http2RawStreamAbortHandler", "raw_abort_match", "{\"rawStreamLogId\":" + rawStreamLogId + ",\"chunkLen\":" + chunk.length + ",\"keepLen\":" + keepLen + ",\"clientActive\":" + clientChannel.isActive() + ",\"partialHex\":\"" + CursorProxyDebugLog.hexPrefix(keepLen > 0 ? Arrays.copyOfRange(chunk, 0, keepLen) : new byte[0], 48) + "\"}");
                    LOG.info("[H2Proxy] abort token matched (raw/SSE bytes), chunkLen=" + chunk.length);
                    final int fl = keepLen;
                    final byte[] ch = chunk;
                    runClient(() -> {
                        if (fl > 0) {
                            byte[] partial = Arrays.copyOfRange(ch, 0, fl);
                            clientChannel.write(new DefaultHttpContent(Unpooled.wrappedBuffer(partial)));
                        }
                        clientChannel.write(new DefaultHttpContent(Unpooled.wrappedBuffer(CONNECT_END_STREAM_FRAME)));
                        ChannelFuture rawLast = clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);
                        rawLast.addListener(f -> CursorProxyDebugLog.line("RAW_LAST_FLUSH", "Http2RawStreamAbortHandler", "raw_last_done", "{\"rawStreamLogId\":" + rawStreamLogId + ",\"success\":" + f.isSuccess() + ",\"clientActive\":" + clientChannel.isActive() + ",\"err\":\"" + CursorProxyDebugLog.esc(f.cause() == null ? "" : f.cause().getClass().getSimpleName() + ":" + f.cause().getMessage()) + "\"}"));
                        rawLast.addListener(ChannelFutureListener.CLOSE);
                    });
                    return;
                }
                tail = CursorStreamAbortIntercept.suffixForOverlap(chunk, needle.length);
                runClient(() -> {
                    clientChannel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(chunk)));
                    if (endStream) {
                        finishClient();
                    }
                });
                return;
            }
            if (msg instanceof io.netty.util.ReferenceCounted) {
                ((io.netty.util.ReferenceCounted) msg).release();
            }
        }

        private void finishClient() {
            if (aborted.get()) {
                return;
            }
            clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT).addListener(ChannelFutureListener.CLOSE);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            LOG.log(Level.WARNING, "[H2Proxy] raw/SSE stream error", cause);
            if (!aborted.getAndSet(true)) {
                runClient(() -> clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT).addListener(ChannelFutureListener.CLOSE));
            }
            ctx.close();
        }
    }

    // ======================== Http2RelayHandler（非拦截路径，纯转发） ========================

    private static class Http2RelayHandler extends ChannelInboundHandlerAdapter {
        private final Channel clientChannel;
        private boolean clientHeadersSent = false;

        Http2RelayHandler(Channel clientChannel) {
            this.clientChannel = clientChannel;
        }

        private void runClient(Runnable r) {
            runOnClient(clientChannel, r);
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof Http2HeadersFrame) {
                Http2HeadersFrame hf = (Http2HeadersFrame) msg;
                if (!clientHeadersSent) {
                    runClient(() -> {
                        writeClientResponseHeaders(clientChannel, hf.headers(), false);
                        clientHeadersSent = true;
                        if (hf.isEndStream()) {
                            finishClient();
                        }
                    });
                } else if (hf.isEndStream()) {
                    runClient(this::finishClient);
                }
                return;
            }
            if (msg instanceof Http2DataFrame) {
                Http2DataFrame df = (Http2DataFrame) msg;
                boolean endStream = df.isEndStream();
                ByteBuf buf = df.content();
                int n = buf.readableBytes();
                if (n > 0) {
                    byte[] data = new byte[n];
                    buf.getBytes(buf.readerIndex(), data);
                    runClient(() -> clientChannel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(data))));
                }
                df.release();
                if (endStream) {
                    runClient(this::finishClient);
                }
                return;
            }
            if (msg instanceof io.netty.util.ReferenceCounted) ((io.netty.util.ReferenceCounted) msg).release();
        }

        private void finishClient() {
            clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT).addListener(ChannelFutureListener.CLOSE);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            LOG.log(Level.WARNING, "[H2Proxy] relay stream error", cause);
            runClient(() -> clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT).addListener(ChannelFutureListener.CLOSE));
            ctx.close();
        }
    }

    /**
     * RunSSE 下行：标准 SSE，由 {@link SseDownstreamFormatter} 写 data 行
     */
    private static void writeSseStreamResponseHeaders(Channel clientChannel, long streamLogId) {
        DefaultHttpResponse resp = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/event-stream; charset=utf-8");
        resp.headers().set(HttpHeaderNames.CACHE_CONTROL, "no-cache, no-transform");
        resp.headers().set("X-Accel-Buffering", "no");
        resp.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
        resp.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        CursorProxyDebugLog.line("S1_SSE_HDR", "writeSseStreamResponseHeaders", "sse_headers", "{\"streamLogId\":" + streamLogId + "}");
        clientChannel.writeAndFlush(resp);
    }

    /**
     * 上游对 RunSSE 常返回 {@code Content-Type: text/event-stream}，但本路径实际向客户端写的是 gRPC Connect 二进制分块。
     * 若透传该头，connect-es 会按 SSE 文本解析，与二进制帧不符，表现为无输出或异常重连。
     * 应对齐<strong>客户端请求</strong>的 {@code Content-Type}（一般为 {@code application/connect+proto}）。
     */
    private static void writeClientConnectWireResponseHeaders(Channel clientChannel, Http2Headers upstream, HttpHeaders clientRequestHeaders, long streamLogId, boolean clientStartedAsRunSsePath) {
        CharSequence st = upstream.status();
        int statusCode = 200;
        try {
            if (st != null) {
                statusCode = Integer.parseInt(st.toString());
            }
        } catch (Exception ignored) {
        }
        DefaultHttpResponse resp = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(statusCode));
        for (Map.Entry<CharSequence, CharSequence> entry : upstream) {
            String name = entry.getKey().toString();
            if (name.startsWith(":")) {
                continue;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            // 下行体为已解压的 Connect 二进制分块，勿透传 hop-by-hop 或整段压缩声明，否则客户端会误解压/误解析
            if ("content-type".equals(lower) || "content-length".equals(lower) || "content-encoding".equals(lower) || "transfer-encoding".equals(lower)) {
                continue;
            }
            resp.headers().add(name, entry.getValue().toString());
        }
        String reqCt = clientRequestHeaders != null ? clientRequestHeaders.get(HttpHeaderNames.CONTENT_TYPE) : null;
        if (reqCt == null || reqCt.isEmpty()) {
            reqCt = "application/connect+proto";
        }
        resp.headers().set(HttpHeaderNames.CONTENT_TYPE, reqCt);
        if (clientRequestHeaders != null) {
            String cpv = clientRequestHeaders.get("connect-protocol-version");
            if (cpv != null && !cpv.isEmpty()) {
                resp.headers().set("connect-protocol-version", cpv);
            }
        }
        resp.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
        resp.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        CursorProxyDebugLog.line("S1_CT", "writeClientConnectWireResponseHeaders", "override_content_type", "{\"streamLogId\":" + streamLogId + ",\"setContentType\":\"" + CursorProxyDebugLog.esc(reqCt) + "\",\"skippedContentEncodingAndTransferHeaders\":true}");
        clientChannel.writeAndFlush(resp);
    }

    /**
     * 从 HTTP/2 响应头构建 HTTP/1.1 响应，透传所有头
     */
    private static void writeClientResponseHeaders(Channel clientChannel, Http2Headers h2h, boolean chunked) {
        CharSequence status = h2h.status();
        int statusCode = status != null ? Integer.parseInt(status.toString()) : 200;
        DefaultHttpResponse resp = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(statusCode));
        for (Map.Entry<CharSequence, CharSequence> entry : h2h) {
            String name = entry.getKey().toString();
            if (name.startsWith(":")) continue;
            resp.headers().add(name, entry.getValue().toString());
        }
        if (chunked) {
            resp.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
        }
        clientChannel.writeAndFlush(resp);
    }

    // ======================== 上游 HTTP/2 连接管理 ========================

    private Future<Channel> getOrCreateUpstreamConn() {
        Channel existing = upstreamConnRef.get();
        if (existing != null && existing.isActive()) {
            Promise<Channel> p = upstreamEventLoopGroup.next().newPromise();
            p.setSuccess(existing);
            return p;
        }
        synchronized (upstreamConnectLock) {
            existing = upstreamConnRef.get();
            if (existing != null && existing.isActive()) {
                Promise<Channel> p = upstreamEventLoopGroup.next().newPromise();
                p.setSuccess(existing);
                return p;
            }
            Future<Channel> pending = pendingUpstreamConnect;
            if (pending != null && !pending.isDone()) {
                return pending;
            }
            Promise<Channel> resultPromise = connectUpstream();
            pendingUpstreamConnect = resultPromise;
            resultPromise.addListener((FutureListener<Channel>) future -> {
                synchronized (upstreamConnectLock) {
                    if (pendingUpstreamConnect == future) {
                        pendingUpstreamConnect = null;
                    }
                }
            });
            return resultPromise;
        }
    }

    private Promise<Channel> connectUpstream() {
        Promise<Channel> resultPromise = upstreamEventLoopGroup.next().newPromise();
        Bootstrap b = new Bootstrap();
        b.group(upstreamEventLoopGroup).channel(NioSocketChannel.class).handler(new Http2UpstreamInitializer(upstreamSslCtx, resultPromise));

        b.connect(CURSOR_API_HOST, CURSOR_API_PORT).addListener((ChannelFutureListener) f -> {
            if (!f.isSuccess()) {
                resultPromise.tryFailure(f.cause());
                return;
            }
            // 勿在此处 upstreamConnRef.set：TCP 已连上但 ALPN 未完成，pipeline 里还没有 Http2MultiplexHandler，
            // 复用该 Channel 会导致 Http2StreamChannelBootstrap 报 IllegalStateException。
        });
        return resultPromise;
    }

    private class Http2UpstreamInitializer extends ChannelInitializer<SocketChannel> {
        private final SslContext sslCtx;
        private final Promise<Channel> connReadyPromise;

        Http2UpstreamInitializer(SslContext sslCtx, Promise<Channel> connReadyPromise) {
            this.sslCtx = sslCtx;
            this.connReadyPromise = connReadyPromise;
        }

        @Override
        protected void initChannel(SocketChannel ch) {
            ch.pipeline().addLast(sslCtx.newHandler(ch.alloc(), CURSOR_API_HOST, CURSOR_API_PORT));
            ch.pipeline().addLast(new ApplicationProtocolNegotiationHandler(ApplicationProtocolNames.HTTP_1_1) {
                @Override
                protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
                    if (ApplicationProtocolNames.HTTP_2.equals(protocol)) {
                        ctx.pipeline().addLast(Http2FrameCodecBuilder.forClient().initialSettings(Http2Settings.defaultSettings()).build());
                        ctx.pipeline().addLast(new Http2MultiplexHandler(new ChannelInboundHandlerAdapter()));
                        LOG.info("[H2Proxy] HTTP/2 negotiated via ALPN, multiplex ready");
                        Channel c = ctx.channel();
                        upstreamConnRef.set(c);
                        c.closeFuture().addListener(cf -> upstreamConnRef.compareAndSet(c, null));
                        connReadyPromise.trySuccess(c);
                    } else {
                        connReadyPromise.tryFailure(new IllegalStateException("Expected h2 but got: " + protocol));
                        ctx.close();
                    }
                }

                @Override
                protected void handshakeFailure(ChannelHandlerContext ctx, Throwable cause) {
                    connReadyPromise.tryFailure(cause);
                    ctx.close();
                }
            });
        }
    }

    // ======================== SSL ========================

    private static SslContext buildUpstreamSslContext() throws SSLException {
        return SslContextBuilder.forClient().applicationProtocolConfig(new ApplicationProtocolConfig(ApplicationProtocolConfig.Protocol.ALPN, ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE, ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT, ApplicationProtocolNames.HTTP_2)).build();
    }

    private SslContext buildMitmSslContext(String host) {
        try {
            X509Certificate cert = CertUtil.genCert(mitmConfig.getIssuer(), mitmConfig.getCaPriKey(), mitmConfig.getCaNotBefore(), mitmConfig.getCaNotAfter(), mitmConfig.getServerPubKey(), host);
            return SslContextBuilder.forServer(mitmConfig.getServerPriKey(), cert).build();
        } catch (Exception e) {
            throw new RuntimeException("[H2Proxy] MITM SSL build failed for " + host, e);
        }
    }

    private static HttpProxyServerConfig loadMitmConfig() throws Exception {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        X509Certificate caCert = CertUtil.loadCert(cl.getResourceAsStream("ca.crt"));
        PrivateKey caPriKey = CertUtil.loadPriKey(cl.getResourceAsStream("ca_private.der"));
        KeyPair kp = CertUtil.genKeyPair();
        HttpProxyServerConfig cfg = new HttpProxyServerConfig();
        cfg.setIssuer(CertUtil.getSubject(caCert));
        cfg.setCaNotBefore(caCert.getNotBefore());
        cfg.setCaNotAfter(caCert.getNotAfter());
        cfg.setCaPriKey(caPriKey);
        cfg.setServerPriKey(kp.getPrivate());
        cfg.setServerPubKey(kp.getPublic());
        return cfg;
    }

    // ======================== 工具方法 ========================

    private static void logRequestHeaders(FullHttpRequest req) {
        StringBuilder sb = new StringBuilder("[H2Proxy] ").append(req.method()).append(' ').append(req.uri());
        String host = req.headers().get(HttpHeaderNames.HOST);
        if (host != null) sb.append(" (host=").append(host).append(')');
        LOG.info(sb.toString());
    }

    private static void sendError(Channel ch) {
        if (!ch.isActive()) return;
        runOnClient(ch, () -> {
            if (!ch.isActive()) return;
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_GATEWAY, Unpooled.copiedBuffer("upstream error\n", StandardCharsets.UTF_8));
            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
            HttpUtil.setContentLength(resp, resp.content().readableBytes());
            ch.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
        });
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}