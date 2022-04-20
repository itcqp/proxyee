package com.github.monkeywie.proxyee.handler;

import cn.hutool.core.thread.ThreadUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.util.AttributeKey;
import org.java_websocket.enums.ReadyState;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * 转发客户端
 */
public class ProxyClient {

    public static Map<ChannelHandlerContext, MyWebsocketClient> channelBooleanMap = new ConcurrentHashMap<ChannelHandlerContext, MyWebsocketClient>();
    private static EventLoopGroup group = new NioEventLoopGroup(100);

    private static MyWebsocketClient getChannel(ChannelHandlerContext ctx, String host, int port) throws InterruptedException, URISyntaxException {
        if (channelBooleanMap.get(ctx) != null) {
            return channelBooleanMap.get(ctx);
        } else {
            String token= (String) ctx.channel().attr(AttributeKey.valueOf("token")).get();
            token = "wss://" + token;
            MyWebsocketClient myWebsocketClient = new MyWebsocketClient(token, ctx);
            myWebsocketClient.connect();
            int i = 0;
            while (true) {
                if (myWebsocketClient.getReadyState().equals(ReadyState.OPEN)) {
                    break;
                }
                ThreadUtil.sleep(1, TimeUnit.SECONDS);
                i++;
                if (i>30) {
                    break;
                }
            }

            return myWebsocketClient;
//            Bootstrap b = new Bootstrap();
//            b.group(group)
//                    .channel(NioSocketChannel.class)
//                    .option(ChannelOption.TCP_NODELAY, true)
//                    .option(ChannelOption.SO_KEEPALIVE, true)
//                    .handler(new SecureChatClientInitializer(conChannel));
//            ChannelFuture channelFuture = b.connect(host, port).sync();
//            channelBooleanMap.put(conChannel, channelFuture.channel());
//            return channelFuture.channel();
        }
    }

    public static void proxy(String host, int port, byte[] bytes, ChannelHandlerContext ctx) throws InterruptedException, UnsupportedEncodingException, URISyntaxException {
        MyWebsocketClient wsClient = getChannel(ctx, host, port);
        String msg = new String(bytes);
        System.out.println("前端发送的消息：" + msg + "-----" + msg.getBytes().length);
        wsClient.send(bytes);
//        while (channel.isOpen()) {
//            channel.writeAndFlush(bytes);
//            break;
//        }
    }
    /**
     * 与远程websocket建立连接
     * */

//    public boolean connectToRemoteWs(FullHttpRequest req, ChannelHandlerContext ctx) {
//        boolean flag = false;
//        ProxySetting servletSetting = HttpUtils.getRouteSetting(req);
//        String targetUrl = servletSetting.getTargetUrl();
//        //远程websocket的地址
//        URI targetUriObj = null;
//        try {
//            targetUriObj = new URI(targetUrl);
//        } catch (URISyntaxException e) {
//            e.printStackTrace();
//        }
//        HttpHost httpHost = URIUtils.extractHost(targetUriObj);
//        String hostStr = httpHost.toString();
//        String websocketStr = hostStr.concat(req.uri());
//
//        try {
//            MyWebsocketClient myWebsocketClient = new MyWebsocketClient(websocketStr, ctx);
//            myWebsocketClient.connect();
//            for (int i = 0; i < 10 ; i++) {
//                if (myWebsocketClient.getReadyState().equals(ReadyState.OPEN)) {
//                    flag = true;
//                    WsConstant.wsClientCtx.put(myWebsocketClient, ctx);
//                    WsConstant.wsCtxClient.put(ctx, myWebsocketClient);
//                    break;
//                }
//                TimeUnit.MILLISECONDS.sleep(200);
//            }
//            if (!flag) {
//                myWebsocketClient.close();
//            }
//        } catch (URISyntaxException | InterruptedException e) {
//            e.printStackTrace();
//        }
//
//        return flag;
//    }

}
