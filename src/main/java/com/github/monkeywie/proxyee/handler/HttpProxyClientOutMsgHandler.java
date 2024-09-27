package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.util.DevinUtil;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.HttpContent;

/**
 * @version 1.0.0
 * @Author chenqp
 * @Date 2024/9/27
 * @describe
 */
public class HttpProxyClientOutMsgHandler extends ChannelOutboundHandlerAdapter {
    private Channel clientChannel;

    public HttpProxyClientOutMsgHandler(Channel clientChannel) {
        this.clientChannel = clientChannel;
    }
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (msg instanceof ByteBuf) {
         DevinUtil.printMsg((ByteBuf) msg, "客户端请求消息内容222");
        }else if (msg instanceof HttpContent) {
            DevinUtil.printMsg((HttpContent) msg, "客户端请求body内容222");
        }
        ctx.write(msg, promise);
    }
}
