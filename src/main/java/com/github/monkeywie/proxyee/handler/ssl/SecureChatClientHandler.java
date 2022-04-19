package com.github.monkeywie.proxyee.handler.ssl;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;

public class SecureChatClientHandler extends ChannelInboundHandlerAdapter {

    private Channel channel;

    private  int discardMsgCount=0;

    public SecureChatClientHandler(){
    }
    public SecureChatClientHandler(Channel channel){
        super();
        this.channel=channel;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        discardMsgCount++;
        byte[] sendBytes=(byte[])msg;
        int length=sendBytes.length;
        System.out.println("远端消息<<<<<<<"+new String(sendBytes)+"<<<<<<<"+length+"--------------"+discardMsgCount);

        while (channel.isOpen()&&discardMsgCount>=2){
            ByteBuf msgBuf = Unpooled.buffer(length);
            msgBuf.writeBytes(sendBytes);
            channel.writeAndFlush(new BinaryWebSocketFrame(msgBuf));
            break;
        }
    }




    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        Channel incoming = ctx.channel();
        System.out.println("Client:"+incoming.remoteAddress()+"异常");
        //当出现异常就关闭连接
        cause.printStackTrace();
        ctx.close();
    }





}
