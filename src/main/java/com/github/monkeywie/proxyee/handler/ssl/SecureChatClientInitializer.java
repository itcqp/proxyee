package com.github.monkeywie.proxyee.handler.ssl;
import io.netty.channel.Channel;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;

import io.netty.handler.codec.bytes.ByteArrayDecoder;
import io.netty.handler.codec.bytes.ByteArrayEncoder;


import javax.net.ssl.SSLEngine;


public class SecureChatClientInitializer extends ChannelInitializer<SocketChannel> {

    private Channel channel;

    public SecureChatClientInitializer() {

    }

    public SecureChatClientInitializer(Channel channel) {
        super();
        this.channel = channel;
    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        ChannelPipeline pipeline = ch.pipeline();
//        String cChatPath = System.getProperty("user.dir") + "/src/main/resources/like.jks";
//        SSLEngine engine = SecureChatSslContextFactory.getClientContext(cChatPath).createSSLEngine();
//        engine.setUseClientMode(true);
//        pipeline.addLast("ssl", new SslHandler(engine)); //加密管道
        pipeline.addLast("decoder", new ByteArrayDecoder());
        pipeline.addLast("encoder", new ByteArrayEncoder());
        pipeline.addLast("handler", new SecureChatClientHandler(channel));
    }









}