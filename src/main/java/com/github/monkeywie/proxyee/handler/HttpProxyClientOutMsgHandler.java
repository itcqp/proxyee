package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.util.DevinUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.HttpContent;
import io.netty.util.ReferenceCountUtil;

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
            //cqptodo websocket 客户端消息解码与自定义发送消息给服务器
            String wsmsg = DevinUtil.decodeWebSocketPayload((ByteBuf) msg);
            System.out.println("客户端请求websocket内容" + wsmsg);
//            ByteBuf bytes = DevinUtil.encodeWebSocketFrame("{\"ver\":\"1.0\",\"cmdId\":2,\"isZip\":0,\"body\":{\"userId\":\"qq_35215932\",\"appId\":\"CSDN-PC\",\"imToken\":\"1727579853874JxO3oRri\",\"groupId\":\"CSDN-private-MSG\"}}\t");
//            ReferenceCountUtil.release(msg);
//            ctx.write(Unpooled.wrappedBuffer(bytes), promise);
//            return;
        }else if (msg instanceof HttpContent) {
            DevinUtil.printMsg((HttpContent) msg, "客户端请求body内容222");
        }
        ctx.write(msg, promise);
    }
}
