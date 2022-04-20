package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.proxy.ProxyConfig;
import com.github.monkeywie.proxyee.proxy.ProxyHandleFactory;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import com.github.monkeywie.proxyee.server.auth.HttpAuthContext;
import com.github.monkeywie.proxyee.server.auth.HttpProxyAuthenticationProvider;
import com.github.monkeywie.proxyee.server.auth.model.HttpToken;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import com.github.monkeywie.proxyee.util.ProtoUtil.RequestProto;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.handler.proxy.ProxyHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.resolver.NoopAddressResolverGroup;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;

import java.net.InetSocketAddress;
import java.net.URL;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class HttpProxyServerHandler extends ChannelInboundHandlerAdapter {
    // 存放已经连接的通道
    private  static ConcurrentMap<String, Channel> ChannelMap=new ConcurrentHashMap();
    private ChannelFuture cf;
    private RequestProto requestProto;
    private int status = 0;
    private final HttpProxyServerConfig serverConfig;
    private final ProxyConfig proxyConfig;
    private final HttpProxyInterceptInitializer interceptInitializer;
    private HttpProxyInterceptPipeline interceptPipeline;
    private final HttpProxyExceptionHandle exceptionHandle;
    private List requestList;
    private boolean isConnect;

    protected ChannelFuture getChannelFuture() {
        return cf;
    }

    protected void setChannelFuture(ChannelFuture cf) {
        this.cf = cf;
    }

    public HttpProxyExceptionHandle getExceptionHandle() {
        return exceptionHandle;
    }

    public HttpProxyInterceptInitializer getInterceptInitializer() {
        return interceptInitializer;
    }

    protected boolean getIsConnect() {
        return isConnect;
    }

    protected void setIsConnect(boolean isConnect) {
        this.isConnect = isConnect;
    }

    protected List getRequestList() {
        return requestList;
    }

    protected void setRequestList(List requestList) {
        this.requestList = requestList;
    }


    public ProxyConfig getProxyConfig() {
        return proxyConfig;
    }

    protected RequestProto getRequestProto() {
        return requestProto;
    }

    protected void setRequestProto(RequestProto requestProto) {
        this.requestProto = requestProto;
    }

    public HttpProxyServerConfig getServerConfig() {
        return serverConfig;
    }

    protected int getStatus() {
        return status;
    }

    protected void setStatus(int status) {
        this.status = status;
    }

    public HttpProxyInterceptPipeline getInterceptPipeline() {
        return interceptPipeline;
    }

    protected void setInterceptPipeline(HttpProxyInterceptPipeline interceptPipeline) {
        this.interceptPipeline = interceptPipeline;
    }

    public HttpProxyServerHandler(HttpProxyServerConfig serverConfig, HttpProxyInterceptInitializer interceptInitializer, ProxyConfig proxyConfig, HttpProxyExceptionHandle exceptionHandle) {
        this.serverConfig = serverConfig;
        this.proxyConfig = proxyConfig;
        this.interceptInitializer = interceptInitializer;
        this.exceptionHandle = exceptionHandle;
    }

    @Override
    public void channelRead(final ChannelHandlerContext ctx, final Object msg) throws Exception {

        if (msg instanceof FullHttpRequest || msg instanceof HttpRequest) {
            HttpRequest request = (HttpRequest) msg;
            if (isWebSocketUpgrade(request)) {
                String token = request.headers().get("host");
                //参数传递
                if (!AttributeKey.exists("token")) {
                    ctx.channel().attr(AttributeKey.newInstance("token")).set(token);
                } else {
                    ctx.channel().attr(AttributeKey.valueOf("token")).set(token);
                }
                super.channelRead(ctx, msg);
                return;
            }
//            if (msg instanceof HttpContent) {
//                if (getStatus() != 2) {
//                    getInterceptPipeline().beforeRequest(ctx.channel(), (HttpContent) msg);
//                } else {
//                    ReferenceCountUtil.release(msg);
//                    setStatus(1);
//                }
//            }
            // 第一次建立连接取host和端口号和处理代理握手
            if (getStatus() == 0) {
                setRequestProto(ProtoUtil.getRequestProto(request));
                if (getRequestProto() == null) { // bad request
                    ctx.channel().close();
                    return;
                }
                // 首次连接处理
                if (getServerConfig().getHttpProxyAcceptHandler() != null
                        && !getServerConfig().getHttpProxyAcceptHandler().onAccept(request, ctx.channel())) {
                    setStatus(2);
                    ctx.channel().close();
                    return;
                }
                // 代理身份验证
                if (!authenticate(ctx, request)) {
                    setStatus(2);
                    ctx.channel().close();
                    return;
                }
                setStatus(1);
                if (HttpMethod.CONNECT.name().equalsIgnoreCase(request.method().name())) {// 建立代理握手
                    setStatus(2);
                    HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpProxyServer.SUCCESS);
                    ctx.writeAndFlush(response);
                    ctx.channel().pipeline().remove("httpCodec");
//                    ctx.channel().pipeline().remove("aggregator");
//                    ctx.channel().pipeline().remove("cw");
//                    ctx.channel().pipeline().remove("WebSocket-protocol");
//                    ctx.channel().pipeline().remove("WebSocket-request");
//                    ctx.channel().pipeline().remove("WebSocket-trequest");
                    // fix issue #42
                    ReferenceCountUtil.release(msg);
                    return;
                }
            }
            //websocket处理
//            handleHttpRequest(ctx,(HttpRequest)msg);
            setInterceptPipeline(buildPipeline());
            getInterceptPipeline().setRequestProto(getRequestProto().copy());
            // fix issue #27
            if (request.uri().indexOf("/") != 0) {
                URL url = new URL(request.uri());
                request.setUri(url.getFile());
            }
            getInterceptPipeline().beforeRequest(ctx.channel(), request);
        } else if (msg instanceof HttpContent) {
            if (getStatus() != 2) {
                getInterceptPipeline().beforeRequest(ctx.channel(), (HttpContent) msg);
            } else {
                ReferenceCountUtil.release(msg);
                setStatus(1);
            }
        }else if (msg instanceof WebSocketFrame) {
            if (msg instanceof CloseWebSocketFrame) {
                System.out.println("进入websocket进行关闭");
                MyWebsocketClient ws = ProxyClient.channelBooleanMap.get(ctx);
                if (ws != null) {
                    ws.close();
                    ProxyClient.channelBooleanMap.remove(ctx);
                }
                ReferenceCountUtil.release(msg);
                return;
            } else if (msg instanceof PingWebSocketFrame) { {
                MyWebsocketClient ws = ProxyClient.channelBooleanMap.get(ctx);
                if (ws != null) {
                    ws.sendPing();
                }
            }
            }
            System.out.println("进入websocket处理");
            super.channelRead(ctx, msg);
            return;
//   判断是否关闭链路的指令
//            if (frame instanceof CloseWebSocketFrame) {
//                socketServerHandshaker.close(ctx.channel(), (CloseWebSocketFrame) frame.retain());
//            }
//            // 判断是否ping消息
//            if (frame instanceof PingWebSocketFrame) {
//                ctx.channel().write(new PongWebSocketFrame(frame.content().retain()));
//                return;
//            }
//            // 本例程仅支持文本消息，不支持二进制消息
//            if (!(frame instanceof TextWebSocketFrame)) {
//                throw new UnsupportedOperationException(String.format("%s frame types not supported", frame.getClass().getName()));
//            }
//            // 返回应答消息
//            String request = ((TextWebSocketFrame) frame).text();
//            System.out.println("服务端收到：" + request);
//            TextWebSocketFrame tws = new TextWebSocketFrame(new Date().toString() + ctx.channel().id() + "：" + request);
//            // 群发
//            group.writeAndFlush(tws);
        }else { // ssl和websocket的握手处理
            ByteBuf byteBuf = (ByteBuf) msg;
            if (getServerConfig().isHandleSsl() && byteBuf.getByte(0) == 22) {// ssl握手
                getRequestProto().setSsl(true);
                int port = ((InetSocketAddress) ctx.channel().localAddress()).getPort();
                SslContext sslCtx = SslContextBuilder
                        .forServer(getServerConfig().getServerPriKey(), CertPool.getCert(port, getRequestProto().getHost(), getServerConfig())).build();
                ctx.pipeline().addFirst("httpCodec", new HttpServerCodec());
                ctx.pipeline().addFirst("sslHandle", sslCtx.newHandler(ctx.alloc()));
                // 重新过一遍pipeline，拿到解密后的的http报文
                ctx.pipeline().fireChannelRead(msg);
                return;
            }
            if (byteBuf.readableBytes() < 8) {
                return;
            }
            // 如果connect后面跑的是HTTP报文，也可以抓包处理
            if (isHttp(byteBuf)) {
                ctx.pipeline().addFirst("httpCodec", new HttpServerCodec());
                ctx.pipeline().fireChannelRead(msg);
                return;
            }
            handleProxyData(ctx.channel(), msg, false);
        }
    }

    private boolean isHttp(ByteBuf byteBuf) {
        byte[] bytes = new byte[8];
        byteBuf.getBytes(0, bytes);
        String methodToken = new String(bytes);
        return methodToken.startsWith("GET ") || methodToken.startsWith("POST ") || methodToken.startsWith("HEAD ")
                || methodToken.startsWith("PUT ") || methodToken.startsWith("DELETE ") || methodToken.startsWith("OPTIONS ")
                || methodToken.startsWith("CONNECT ") || methodToken.startsWith("TRACE ");
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        if (getChannelFuture() != null) {
            getChannelFuture().channel().close();
        }
        ctx.channel().close();
        if (getServerConfig().getHttpProxyAcceptHandler() != null) {
            getServerConfig().getHttpProxyAcceptHandler().onClose(ctx.channel());
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (getChannelFuture() != null) {
            getChannelFuture().channel().close();
        }
        System.out.println("异常"+cause.getMessage());
        cause.printStackTrace();
        ctx.channel().close();
        exceptionHandle.beforeCatch(ctx.channel(), cause);
    }

    private boolean authenticate(ChannelHandlerContext ctx, HttpRequest request) {
        if (serverConfig.getAuthenticationProvider() != null) {
            HttpProxyAuthenticationProvider authProvider = serverConfig.getAuthenticationProvider();

            // Disable auth for request?
            if (!authProvider.matches(request)) {
                return true;
            }

            HttpToken httpToken = authProvider.authenticate(request);
            if (httpToken == null) {
                HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpProxyServer.UNAUTHORIZED);
                response.headers().set(HttpHeaderNames.PROXY_AUTHENTICATE, authProvider.authType() + " realm=\"" + authProvider.authRealm() + "\"");
                ctx.writeAndFlush(response);
                return false;
            }
            HttpAuthContext.setToken(ctx.channel(), httpToken);
        }
        return true;
    }

    private void handleProxyData(Channel channel, Object msg, boolean isHttp) throws Exception {
        if (getChannelFuture() == null) {
            // connection异常 还有HttpContent进来，不转发
            if (isHttp && !(msg instanceof HttpRequest)) {
                return;
            }
            if (getInterceptPipeline() == null) {
                setInterceptPipeline(buildOnlyConnectPipeline());
                getInterceptPipeline().setRequestProto(getRequestProto().copy());
            }
            getInterceptPipeline().beforeConnect(channel);

            // by default we use the proxy config set in the pipeline
            ProxyHandler proxyHandler = ProxyHandleFactory.build(getInterceptPipeline().getProxyConfig() == null ?
                    proxyConfig : getInterceptPipeline().getProxyConfig());

            RequestProto requestProto = getInterceptPipeline().getRequestProto();
            if (isHttp) {
                HttpRequest httpRequest = (HttpRequest) msg;
                // 检查requestProto是否有修改
                RequestProto newRP = ProtoUtil.getRequestProto(httpRequest);
                if (!newRP.equals(requestProto)) {
                    // 更新Host请求头
                    if ((getRequestProto().getSsl() && getRequestProto().getPort() == 443)
                            || (!getRequestProto().getSsl() && getRequestProto().getPort() == 80)) {
                        httpRequest.headers().set(HttpHeaderNames.HOST, getRequestProto().getHost());
                    } else {
                        httpRequest.headers().set(HttpHeaderNames.HOST, getRequestProto().getHost() + ":" + getRequestProto().getPort());
                    }
                }
            }

            /*
             * 添加SSL client hello的Server Name Indication extension(SNI扩展) 有些服务器对于client
             * hello不带SNI扩展时会直接返回Received fatal alert: handshake_failure(握手错误)
             * 例如：https://cdn.mdn.mozilla.net/static/img/favicon32.7f3da72dcea1.png
             */
            ChannelInitializer channelInitializer = isHttp ? new HttpProxyInitializer(channel, requestProto, proxyHandler)
                    : new TunnelProxyInitializer(channel, proxyHandler);
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(getServerConfig().getProxyLoopGroup()) // 注册线程池
                    .channel(NioSocketChannel.class) // 使用NioSocketChannel来作为连接用的channel类
                    .handler(channelInitializer);
            if (proxyHandler != null) {
                // 代理服务器解析DNS和连接
                bootstrap.resolver(NoopAddressResolverGroup.INSTANCE);
            } else {
                bootstrap.resolver(getServerConfig().resolver());
            }
            setRequestList(new LinkedList());
            setChannelFuture(bootstrap.connect(getRequestProto().getHost(), getRequestProto().getPort()));
            getChannelFuture().addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    future.channel().writeAndFlush(msg);
                    synchronized (requestList) {
                        getRequestList().forEach(obj -> future.channel().writeAndFlush(obj));
                        getRequestList().clear();
                        setIsConnect(true);
                    }
                } else {
                    getRequestList().forEach(obj -> ReferenceCountUtil.release(obj));
                    getRequestList().clear();
                    getExceptionHandle().beforeCatch(channel, future.cause());
                    future.channel().close();
                    channel.close();
                }
            });
        } else {
            synchronized (getRequestList()) {
                if (getIsConnect()) {
                    getChannelFuture().channel().writeAndFlush(msg);
                } else {
                    getRequestList().add(msg);
                }
            }
        }
    }

    private HttpProxyInterceptPipeline buildPipeline() {
        HttpProxyInterceptPipeline interceptPipeline = new HttpProxyInterceptPipeline(new HttpProxyIntercept() {
            @Override
            public void beforeRequest(Channel clientChannel, HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline)
                    throws Exception {
                handleProxyData(clientChannel, httpRequest, true);
                if (HttpHeaderValues.WEBSOCKET.toString().equals(httpRequest.headers().get(HttpHeaderNames.UPGRADE))) {
                    System.out.println("请求websocket:" + httpRequest.toString());
                }
            }

            @Override
            public void beforeRequest(Channel clientChannel, HttpContent httpContent, HttpProxyInterceptPipeline pipeline)
                    throws Exception {
                handleProxyData(clientChannel, httpContent, true);
            }

            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse,
                                      HttpProxyInterceptPipeline pipeline) throws Exception {
                clientChannel.writeAndFlush(httpResponse);
                if (HttpHeaderValues.WEBSOCKET.toString().equals(httpResponse.headers().get(HttpHeaderNames.UPGRADE))) {
                    // websocket转发原始报文
                    System.out.println("11websocket:" + httpResponse.toString());
                    proxyChannel.pipeline().remove("httpCodec");
                    clientChannel.pipeline().remove("httpCodec");
                }
            }

            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent,
                                      HttpProxyInterceptPipeline pipeline) throws Exception {
                clientChannel.writeAndFlush(httpContent);
            }
        });
        getInterceptInitializer().init(interceptPipeline);
        return interceptPipeline;
    }

    // fix issue #186: 不拦截https报文时，暴露一个扩展点用于代理设置，并且保持一致的编程接口
    private HttpProxyInterceptPipeline buildOnlyConnectPipeline() {
        HttpProxyInterceptPipeline interceptPipeline = new HttpProxyInterceptPipeline(new HttpProxyIntercept());
        getInterceptInitializer().init(interceptPipeline);
        return interceptPipeline;
    }

    /**
     * @author lsc
     * <p> 处理http请求升级</p>
     */
    private void handleHttpRequest(ChannelHandlerContext ctx,
                                   HttpRequest req) throws Exception {

        // 该请求是不是websocket upgrade请求
        if (isWebSocketUpgrade(req)) {
            String ws = "ws://127.0.0.1:9999";
            WebSocketServerHandshakerFactory factory = new WebSocketServerHandshakerFactory(ws, null, false);
            WebSocketServerHandshaker handshaker = factory.newHandshaker(req);

            if (handshaker == null) {// 请求头不合法, 导致handshaker没创建成功
                WebSocketServerHandshakerFactory.sendUnsupportedVersionResponse(ctx.channel());
            } else {
                // 响应该请求
                handshaker.handshake(ctx.channel(), req);
            }
            return;
        }
    }

    //n1.GET? 2.Upgrade头 包含websocket字符串?
    private boolean isWebSocketUpgrade(HttpRequest req) {
        HttpHeaders headers = req.headers();
        return req.method().equals(HttpMethod.GET)
                && "websocket".equals(headers.get(HttpHeaderNames.UPGRADE));
    }

}
