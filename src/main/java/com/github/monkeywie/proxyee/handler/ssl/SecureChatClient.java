package com.github.monkeywie.proxyee.handler.ssl;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class SecureChatClient {
    public void start(String host,int port) throws Exception{
        EventLoopGroup group = new NioEventLoopGroup();
        try{
            Bootstrap b = new Bootstrap();
            b.group(group).channel(NioSocketChannel.class).handler(new SecureChatClientInitializer());

            // Start the connection attempt.
            Channel ch = b.connect(host, port).sync().channel();
            // Read commands from the stdin.
            ChannelFuture lastWriteFuture = null;
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            StringBuffer sbf=new StringBuffer();
            sbf.append("CONNECT /console?uuid=5cc4ec48-b00d-6320-3384-4ca7e1745678 HTTP/1.0\r\n");
            sbf.append("HOST: 192.168.212.175\r\n");
            sbf.append("Cookie: session_id=OpaqueRef:8ed4001b-9ee6-4330-b945-fafafd67fd69");
            sbf.append("\r\n");
            sbf.append("\r\n");
            System.out.println(sbf.toString());

            ByteBuf msgBuf = Unpooled.buffer(sbf.toString().getBytes().length);
            msgBuf.writeBytes(sbf.toString().getBytes());
            ch.writeAndFlush(sbf.toString());
            while (true){
                String line = in.readLine();
                if (line .equals("")) {
                    ch.writeAndFlush("".getBytes());

                }else{
                    ch.writeAndFlush("RFB 003.008\n".getBytes("unicode"));
                }
                // Sends the received line to the server.

                // If user typed the 'bye' command, wait until the server closes
                // the connection.
                if ("bye".equals(line.toLowerCase())) {
                    ch.closeFuture().sync();
                    break;
                }
            }

            // Wait until all messages are flushed before closing the channel.
            if (lastWriteFuture != null) {
                lastWriteFuture.sync();
            }
        }finally{
            group.shutdownGracefully();
        }
    }

    public static void main(String[] args) throws Exception {
        new SecureChatClient().start("192.168.212.175", 4430);
    }
}
