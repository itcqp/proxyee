package com.github.monkeywie.proxyee.intercept.cursor;

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
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.concurrent.Promise;

import javax.net.ssl.SSLException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Cursor HTTP/2 MITM 中转代理（独立 Netty 服务）。
 *
 * <p>作为系统代理运行，拦截 Cursor IDE 的所有 HTTPS 流量：
 * <ul>
 *   <li>仅对 api2.cursor.sh 的 /agent.v1.AgentService/RunSSE 做 HTTP/2 转发 + 终止扫描</li>
 *   <li>所有其他请求透明转发（TCP 隧道 或 HTTP/2 relay），不影响 IDE 正常功能</li>
 * </ul>
 */
public class CursorHttp2StreamAbortIntercept {

    private static final Logger LOG = Logger.getLogger(CursorHttp2StreamAbortIntercept.class.getName());

    public static final String DEFAULT_ABORT_TOKEN = "zmgnb666";

    private static final String CURSOR_API_HOST = "api2.cursor.sh";
    private static final int CURSOR_API_PORT = 443;
    private static final String INTERCEPT_URI_KEYWORD = "/agent.v1.AgentService/RunSSE";
    private static final String INTERCEPT_HOST_KEYWORD = "cursor.sh";

    @FunctionalInterface
    public interface HeaderModifier {
        void modify(HttpHeaders headers);
    }

    private final byte[] abortNeedle;
    private final HeaderModifier headerModifier;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel serverChannel;

    private final AtomicReference<Channel> upstreamConnRef = new AtomicReference<>();
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

        ServerBootstrap b = new ServerBootstrap();
        b.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline()
                                .addLast("httpCodec", new HttpServerCodec())
                                .addLast("aggregator", new HttpObjectAggregator(10 * 1024 * 1024))
                                .addLast("proxy", new ProxyHandler());
                    }
                })
                .childOption(ChannelOption.AUTO_READ, true);

        serverChannel = b.bind(port).sync().channel();
        LOG.info("[H2Proxy] server started on port " + port);
    }

    public void stop() {
        if (serverChannel != null) serverChannel.close();
        if (bossGroup != null) bossGroup.shutdownGracefully();
        if (workerGroup != null) workerGroup.shutdownGracefully();
        Channel conn = upstreamConnRef.get();
        if (conn != null && conn.isActive()) conn.close();
        LOG.info("[H2Proxy] server stopped");
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
            boolean match = host != null
                    && host.toLowerCase().contains(INTERCEPT_HOST_KEYWORD)
                    && uri.contains(INTERCEPT_URI_KEYWORD);

            if (match) {
                LOG.info("[H2Proxy] intercepting RunSSE: host=" + host + " uri=" + uri);
                handleRunSSE(ctx, req);
            } else {
                LOG.info("[H2Proxy] relay (not RunSSE): host=" + host + " uri=" + uri);
                handleRelayViaH2(ctx, req);
            }
        }

        /** CONNECT 隧道处理 */
        private void handleConnect(ChannelHandlerContext ctx, FullHttpRequest req) {
            String hostAndPort = req.uri();
            String host = hostAndPort.contains(":")
                    ? hostAndPort.substring(0, hostAndPort.lastIndexOf(':'))
                    : hostAndPort;
            int port = 443;
            if (hostAndPort.contains(":")) {
                try { port = Integer.parseInt(hostAndPort.substring(hostAndPort.lastIndexOf(':') + 1)); }
                catch (NumberFormatException ignored) {}
            }

            if (host.toLowerCase().equals(CURSOR_API_HOST)) {
                LOG.info("[H2Proxy] CONNECT to " + hostAndPort + " → MITM TLS");
                doMitmConnect(ctx, host);
            } else {
                LOG.info("[H2Proxy] CONNECT to " + hostAndPort + " → TCP tunnel (passthrough)");
                doTcpTunnel(ctx, host, port);
            }
        }

        /** 对 api2.cursor.sh 做 MITM TLS（拆开 SSL 检查内部 HTTP 请求） */
        private void doMitmConnect(ChannelHandlerContext ctx, String host) {
            DefaultHttpResponse resp = new DefaultHttpResponse(
                    HttpVersion.HTTP_1_1, new HttpResponseStatus(200, "Connection Established"));
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

        /** 对非 api2 的 cursor.sh 主机，建立 TCP 隧道直接透传（不做 MITM） */
        private void doTcpTunnel(ChannelHandlerContext ctx, String host, int port) {
            Channel clientCh = ctx.channel();
            Bootstrap b = new Bootstrap();
            b.group(clientCh.eventLoop())
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
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
                DefaultHttpResponse resp = new DefaultHttpResponse(
                        HttpVersion.HTTP_1_1, new HttpResponseStatus(200, "Connection Established"));
                clientCh.writeAndFlush(resp).addListener((ChannelFutureListener) wf -> {
                    if (!wf.isSuccess()) { remoteCh.close(); return; }
                    ChannelPipeline p = ctx.pipeline();
                    p.remove("aggregator");
                    p.remove("httpCodec");
                    p.remove("proxy");
                    p.addLast(new TunnelRelayHandler(remoteCh));
                });
            });
        }

        /** 匹配 RunSSE → 走 HTTP/2 转发 + abort 扫描 */
        private void handleRunSSE(ChannelHandlerContext ctx, FullHttpRequest req) {
            HttpHeaders forwardHeaders = req.headers().copy();
            if (headerModifier != null) {
                headerModifier.modify(forwardHeaders);
            }
            ByteBuf bodyCopy = req.content().copy();
            HttpMethod method = req.method();

            // #region agent log
            debugLog("handleRunSSE", "A", "RunSSE intercepted", "bodyBytes", bodyCopy.readableBytes());
            // #endregion

            getOrCreateUpstreamConn(ctx.channel().eventLoop()).addListener(
                    (GenericFutureListener<Future<Channel>>) future -> {
                        if (!future.isSuccess()) {
                            bodyCopy.release();
                            sendError(ctx.channel());
                            return;
                        }
                        forwardViaHttp2(ctx.channel(), future.getNow(), bodyCopy, method,
                                forwardHeaders, req.uri(), true);
                    });
        }

        /** 非匹配请求 → 走 HTTP/2 转发（不扫描，纯 relay） */
        private void handleRelayViaH2(ChannelHandlerContext ctx, FullHttpRequest req) {
            HttpHeaders forwardHeaders = req.headers().copy();
            ByteBuf bodyCopy = req.content().copy();
            HttpMethod method = req.method();

            getOrCreateUpstreamConn(ctx.channel().eventLoop()).addListener(
                    (GenericFutureListener<Future<Channel>>) future -> {
                        if (!future.isSuccess()) {
                            bodyCopy.release();
                            sendError(ctx.channel());
                            return;
                        }
                        forwardViaHttp2(ctx.channel(), future.getNow(), bodyCopy, method,
                                forwardHeaders, req.uri(), false);
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
        TunnelRelayHandler(Channel other) { this.other = other; }

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
     * @param scanAbort true=扫描 abort token（RunSSE），false=纯 relay
     */
    private void forwardViaHttp2(Channel clientChannel, Channel http2Conn,
                                  ByteBuf bodyCopy, HttpMethod method,
                                  HttpHeaders forwardHeaders, String uri, boolean scanAbort) {
        if (!http2Conn.isActive()) {
            bodyCopy.release();
            sendError(clientChannel);
            upstreamConnRef.set(null);
            return;
        }

        Http2StreamChannelBootstrap streamBoot = new Http2StreamChannelBootstrap(http2Conn);
        streamBoot.handler(scanAbort
                ? new Http2StreamHandler(clientChannel, abortNeedle)
                : new Http2RelayHandler(clientChannel));

        streamBoot.open().addListener((GenericFutureListener<Future<Http2StreamChannel>>) f -> {
            if (!f.isSuccess()) {
                LOG.log(Level.SEVERE, "[H2Proxy] failed to open HTTP/2 stream", f.cause());
                bodyCopy.release();
                sendError(clientChannel);
                return;
            }
            Http2StreamChannel streamChannel = f.getNow();
            Http2Headers h2Headers = buildHttp2Headers(forwardHeaders, uri, method);
            streamChannel.write(new DefaultHttp2HeadersFrame(h2Headers, false));
            streamChannel.writeAndFlush(new DefaultHttp2DataFrame(bodyCopy, true));

            LOG.info("[H2Proxy] HTTP/2 stream opened, stream-id=" + streamChannel.stream().id()
                    + " uri=" + uri + " scanAbort=" + scanAbort
                    + " bodyBytes=" + bodyCopy.capacity());
        });
    }

    private Http2Headers buildHttp2Headers(HttpHeaders httpHeaders, String uri, HttpMethod method) {
        Http2Headers h2h = new DefaultHttp2Headers();
        h2h.method(method.name());
        h2h.scheme("https");
        h2h.authority(CURSOR_API_HOST);
        h2h.path(uri);
        for (Map.Entry<String, String> entry : httpHeaders) {
            String name = entry.getKey().toLowerCase();
            if (name.equals("host") || name.equals("connection")
                    || name.equals("keep-alive") || name.equals("transfer-encoding")
                    || name.equals("upgrade") || name.equals("proxy-connection")
                    || name.equals("content-length")) {
                continue;
            }
            h2h.add(name, entry.getValue());
        }
        return h2h;
    }

    // ======================== Http2StreamHandler（RunSSE，abort 扫描） ========================

    /**
     * Connect 协议结束帧：告诉客户端流正常结束（不是中断）。
     * 格式：[0x02=flags(JSON,not-compressed)] [0x00000002=length] [0x7B 0x7D = "{}"]
     */
    private static final byte[] CONNECT_END_STREAM_FRAME = {0x02, 0x00, 0x00, 0x00, 0x02, 0x7B, 0x7D};

    private class Http2StreamHandler extends ChannelInboundHandlerAdapter {
        private final Channel clientChannel;
        private final byte[] needle;
        private byte[] tail;
        private final AtomicBoolean aborted = new AtomicBoolean(false);
        private boolean clientHeadersSent = false;

        Http2StreamHandler(Channel clientChannel, byte[] needle) {
            this.clientChannel = clientChannel;
            this.needle = needle;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof Http2HeadersFrame) {
                Http2HeadersFrame hf = (Http2HeadersFrame) msg;
                if (!clientHeadersSent) {
                    writeClientResponseHeaders(clientChannel, hf.headers(), true);
                    clientHeadersSent = true;
                }
                if (hf.isEndStream()) finishClient();
                return;
            }
            if (msg instanceof Http2DataFrame) {
                Http2DataFrame df = (Http2DataFrame) msg;
                boolean endStream = df.isEndStream();
                if (aborted.get()) { df.release(); return; }

                ByteBuf buf = df.content();
                int n = buf.readableBytes();
                if (n == 0) { df.release(); if (endStream) finishClient(); return; }

                byte[] chunk = new byte[n];
                buf.getBytes(buf.readerIndex(), chunk);
                df.release();

                // 转发原始字节给客户端
                clientChannel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(chunk)));

                // 扫描原始字节（Connect 协议中文本在 protobuf 帧内是明文 UTF-8）
                if (CursorStreamAbortIntercept.containsAbortPattern(tail, chunk, needle)) {
                    LOG.info("[H2Proxy] abort token matched → RST_STREAM(CANCEL) + Connect end frame"
                            + " (chunkLen=" + chunk.length + ")");
                    aborted.set(true);

                    // 向上游发 RST_STREAM(CANCEL)，停止服务端继续生成
                    ctx.channel().writeAndFlush(new DefaultHttp2ResetFrame(Http2Error.CANCEL))
                            .addListener(ChannelFutureListener.CLOSE);

                    // 向客户端注入 Connect 协议结束帧，让客户端认为流正常结束
                    clientChannel.write(
                            new DefaultHttpContent(Unpooled.wrappedBuffer(CONNECT_END_STREAM_FRAME)));
                    clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT)
                            .addListener(ChannelFutureListener.CLOSE);
                    // #region agent log
                    debugLog("abort_done_frame_sent", "C", "connect done frame + LastHttpContent sent to client");
                    // #endregion
                    return;
                }
                tail = CursorStreamAbortIntercept.suffixForOverlap(chunk, needle.length);
                if (endStream) finishClient();
                return;
            }
            if (msg instanceof io.netty.util.ReferenceCounted)
                ((io.netty.util.ReferenceCounted) msg).release();
        }

        private void finishClient() {
            if (aborted.get()) return;
            clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT)
                    .addListener(ChannelFutureListener.CLOSE);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            LOG.log(Level.WARNING, "[H2Proxy] RunSSE stream error", cause);
            if (!aborted.getAndSet(true))
                clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT)
                        .addListener(ChannelFutureListener.CLOSE);
            ctx.close();
        }
    }

    // ======================== Http2RelayHandler（非 RunSSE，纯转发） ========================

    private static class Http2RelayHandler extends ChannelInboundHandlerAdapter {
        private final Channel clientChannel;
        private boolean clientHeadersSent = false;

        Http2RelayHandler(Channel clientChannel) {
            this.clientChannel = clientChannel;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof Http2HeadersFrame) {
                Http2HeadersFrame hf = (Http2HeadersFrame) msg;
                if (!clientHeadersSent) {
                    writeClientResponseHeaders(clientChannel, hf.headers(), false);
                    clientHeadersSent = true;
                }
                if (hf.isEndStream()) finishClient();
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
                    clientChannel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(data)));
                }
                df.release();
                if (endStream) finishClient();
                return;
            }
            if (msg instanceof io.netty.util.ReferenceCounted)
                ((io.netty.util.ReferenceCounted) msg).release();
        }

        private void finishClient() {
            clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT)
                    .addListener(ChannelFutureListener.CLOSE);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            LOG.log(Level.WARNING, "[H2Proxy] relay stream error", cause);
            clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT)
                    .addListener(ChannelFutureListener.CLOSE);
            ctx.close();
        }
    }

    /** 从 HTTP/2 响应头构建 HTTP/1.1 响应，透传所有头 */
    private static void writeClientResponseHeaders(Channel clientChannel, Http2Headers h2h, boolean chunked) {
        CharSequence status = h2h.status();
        int statusCode = status != null ? Integer.parseInt(status.toString()) : 200;
        DefaultHttpResponse resp = new DefaultHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(statusCode));
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

    private Future<Channel> getOrCreateUpstreamConn(EventLoop eventLoop) {
        Channel existing = upstreamConnRef.get();
        if (existing != null && existing.isActive()) {
            Promise<Channel> p = eventLoop.newPromise();
            p.setSuccess(existing);
            return p;
        }
        return connectUpstream(eventLoop);
    }

    private Future<Channel> connectUpstream(EventLoop callerEventLoop) {
        Promise<Channel> resultPromise = callerEventLoop.newPromise();
        NioEventLoopGroup connGroup = new NioEventLoopGroup(1);
        Bootstrap b = new Bootstrap();
        b.group(connGroup)
                .channel(NioSocketChannel.class)
                .handler(new Http2UpstreamInitializer(upstreamSslCtx, resultPromise));

        b.connect(CURSOR_API_HOST, CURSOR_API_PORT).addListener((ChannelFutureListener) f -> {
            if (!f.isSuccess()) {
                connGroup.shutdownGracefully();
                resultPromise.tryFailure(f.cause());
                return;
            }
            Channel conn = f.channel();
            upstreamConnRef.set(conn);
            LOG.info("[H2Proxy] connected to upstream " + CURSOR_API_HOST + ":" + CURSOR_API_PORT);
            conn.closeFuture().addListener(cf -> {
                upstreamConnRef.compareAndSet(conn, null);
                connGroup.shutdownGracefully();
            });
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
                        ctx.pipeline().addLast(Http2FrameCodecBuilder.forClient()
                                .initialSettings(Http2Settings.defaultSettings()).build());
                        ctx.pipeline().addLast(new Http2MultiplexHandler(new ChannelInboundHandlerAdapter()));
                        LOG.info("[H2Proxy] HTTP/2 negotiated via ALPN");
                        connReadyPromise.trySuccess(ctx.channel());
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
        return SslContextBuilder.forClient()
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2))
                .build();
    }

    private SslContext buildMitmSslContext(String host) {
        try {
            X509Certificate cert = CertUtil.genCert(
                    mitmConfig.getIssuer(), mitmConfig.getCaPriKey(),
                    mitmConfig.getCaNotBefore(), mitmConfig.getCaNotAfter(),
                    mitmConfig.getServerPubKey(), host);
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
        FullHttpResponse resp = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_GATEWAY,
                Unpooled.copiedBuffer("upstream error\n", StandardCharsets.UTF_8));
        resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
        HttpUtil.setContentLength(resp, resp.content().readableBytes());
        ch.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
    }

    // #region agent log
    private static final String DEBUG_LOG_PATH = "d:\\devin\\playgame\\proxyee\\.cursor\\debug.log";
    private static void debugLog(String location, String hypothesisId, String message, Object... kvPairs) {
        try {
            StringBuilder sb = new StringBuilder("{");
            sb.append("\"timestamp\":").append(System.currentTimeMillis());
            sb.append(",\"location\":\"").append(location).append("\"");
            sb.append(",\"hypothesisId\":\"").append(hypothesisId).append("\"");
            sb.append(",\"message\":\"").append(message.replace("\"", "\\\"")).append("\"");
            sb.append(",\"data\":{");
            for (int i = 0; i + 1 < kvPairs.length; i += 2) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(kvPairs[i]).append("\":");
                Object v = kvPairs[i + 1];
                if (v instanceof String) sb.append("\"").append(((String) v).replace("\"", "\\\"")).append("\"");
                else sb.append(v);
            }
            sb.append("}}\n");
            java.io.FileWriter fw = new java.io.FileWriter(DEBUG_LOG_PATH, true);
            fw.write(sb.toString());
            fw.close();
        } catch (Exception ignored) {}
    }
    // #endregion
}
