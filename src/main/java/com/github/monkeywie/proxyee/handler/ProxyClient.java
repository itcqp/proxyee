package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.handler.ssl.SecureChatClientInitializer;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;

import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 转发客户端
 */
public class ProxyClient {

    public static Map<Channel, Channel> channelBooleanMap = new ConcurrentHashMap<Channel, Channel>();
    private static EventLoopGroup group = new NioEventLoopGroup(100);

    private static Channel getChannel(Channel conChannel, String host, int port) throws InterruptedException {
        if (channelBooleanMap.get(conChannel) != null) {
            return channelBooleanMap.get(conChannel);
        } else {
            Bootstrap b = new Bootstrap();
            b.group(group)
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .option(ChannelOption.SO_KEEPALIVE, true)
                    .handler(new SecureChatClientInitializer(conChannel));
            ChannelFuture channelFuture = b.connect(host, port).sync();
            channelBooleanMap.put(conChannel, channelFuture.channel());
            return channelFuture.channel();
        }
    }

    public static void proxy(String host, int port, byte[] bytes, ChannelHandlerContext ctx) throws InterruptedException, UnsupportedEncodingException {
        Channel channel = getChannel(ctx.channel(), host, port);
        String msg = new String(bytes);
        System.out.println("前端发送的消息：" + msg + "-----" + msg.getBytes().length);
        while (channel.isOpen()) {
            channel.writeAndFlush(bytes);
            break;
        }
    }


}
