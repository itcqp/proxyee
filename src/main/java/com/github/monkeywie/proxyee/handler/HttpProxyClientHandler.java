package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.util.DevinUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.DecoderResult;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;

import java.nio.charset.StandardCharsets;

public class HttpProxyClientHandler extends ChannelInboundHandlerAdapter {

    private Channel clientChannel;

    public HttpProxyClientHandler(Channel clientChannel) {
        this.clientChannel = clientChannel;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        //客户端channel已关闭则不转发了
        if (!clientChannel.isOpen()) {
            ReferenceCountUtil.release(msg);
            return;
        }
        HttpProxyServerHandler serverHandle = (HttpProxyServerHandler) clientChannel.pipeline().get("serverHandle");
        HttpProxyInterceptPipeline interceptPipeline = serverHandle.getInterceptPipeline();
        HttpServerCodec httpServerCodec  = (HttpServerCodec) clientChannel.pipeline().get("httpCodec");
        if (msg instanceof HttpResponse) {
            System.out.println("服务器返回消息 HttpResponse");
            DecoderResult decoderResult = ((HttpResponse) msg).decoderResult();
            Throwable cause = decoderResult.cause();
            if(cause != null){
                ReferenceCountUtil.release(msg);
                this.exceptionCaught(ctx, cause);
                return;
            }
            interceptPipeline.afterResponse(clientChannel, ctx.channel(), (HttpResponse) msg);
        } else if (msg instanceof HttpContent) {
            System.out.println("服务器返回消息 httpcontent");
            HttpContent content = (HttpContent) msg;
            ByteBuf contentBuf = content.content();
            if (contentBuf.isReadable()) {
                printMsg(contentBuf,"响应body 内容");
            }
            interceptPipeline.afterResponse(clientChannel, ctx.channel(), (HttpContent) msg);
        } else if (msg instanceof ByteBuf)  {
            ByteBuf tmsg =((ByteBuf)msg);
            printMsg(tmsg, "返回消息");
//            String requestBody = "我太牛逼了啊，哈哈哈哈";
//            ByteBuf fullMessage = DevinUtil.getWebsocketMst81(requestBody);
//            clientChannel.writeAndFlush(fullMessage);
            clientChannel.writeAndFlush(msg);
        } else {
            clientChannel.writeAndFlush(msg);
        }
    }

    private static ByteBuf getWebsocketMst81(String requestBody) {
        byte[] messageBytes = requestBody.getBytes(StandardCharsets.UTF_8);
        int length = messageBytes.length;

// 设置帧头，0x81 表示文本帧，length 的 16 进制表示
        ByteBuf prefix = Unpooled.copiedBuffer(new byte[]{(byte) 0x81, (byte) length});
        ByteBuf content = Unpooled.copiedBuffer(messageBytes);

// 合并前缀和内容
        ByteBuf fullMessage = Unpooled.wrappedBuffer(prefix, content);
        return fullMessage;
    }

    private static ByteBuf printMsg(ByteBuf byteBuf, String pre) {
        ByteBuf copy = byteBuf.copy();
        System.out.println("16进制--"+ByteBufUtil.hexDump(copy));
        byte[] bytes = new byte[copy.readableBytes()];
        copy.readBytes(bytes);

        // 将byte数组转换为字符串
        String text  = new String(bytes);
        // 输出字符串
        System.out.println(pre + "：" + text);
        // 释放副本
        copy.release();
        return copy;
    }
    private static ByteBuf hexStringToByteBuf(String hexString) {
        int len = hexString.length() / 2;
        byte[] data = new byte[len];
        for (int i = 0; i < len; i++) {
            data[i] = (byte) Integer.parseInt(hexString.substring(2 * i, 2 * i + 2), 16);
        }
        return Unpooled.wrappedBuffer(data);
    }
    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        ctx.channel().close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        System.out.println("服务端消息监听handle异常了"+cause.getMessage());
        ctx.channel().close();
        clientChannel.close();
        HttpProxyExceptionHandle exceptionHandle = ((HttpProxyServerHandler) clientChannel.pipeline()
                .get("serverHandle")).getExceptionHandle();
        exceptionHandle.afterCatch(clientChannel, ctx.channel(), cause);
    }
}
