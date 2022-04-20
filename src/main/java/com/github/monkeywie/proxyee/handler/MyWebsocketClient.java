package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.proxy.WsConstant;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import lombok.extern.slf4j.Slf4j;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;

/**
 * //TODO
 *
 * @author zhuquanwen
 * @vesion 1.0
 * @date 2019/7/17 9:33
 * @since jdk1.8
 */


@Slf4j
public class MyWebsocketClient extends WebSocketClient {
    private ChannelHandlerContext ctx;

    public MyWebsocketClient(String uri, ChannelHandlerContext ctx) throws URISyntaxException {
        super(new URI(uri));
        this.ctx = ctx;

    }

    @Override
    public void onOpen(ServerHandshake arg0) {
        System.out.println("------ WebSocket onOpen ------"+uri.toString());
        WsConstant.wsClientCtx.put(this, ctx);
    }

    @Override
    public void onClose(int arg0, String arg1, boolean arg2) {
        System.out.println("------ WebSocket onClose ------"+uri.toString());
        ProxyClient.channelBooleanMap.remove(ctx);
        if (ctx.channel().isActive()) {
            ctx.channel().close();
        }

    }

    @Override
    public void onError(Exception arg0) {
        System.out.println("------ WebSocket onError ------");
//        if (ctx.channel().isActive()) {
//            ctx.channel().close();
//        }
    }

    @Override
    public void onMessage(String arg0) {
        System.out.println("-------- 接收到服务端数据： " + arg0 + "--------");
        if (ctx != null && ctx.channel() != null && ctx.channel().isActive()) {
            ctx.writeAndFlush(new TextWebSocketFrame(arg0));
        } else {
            //TODO 暂时这样，不知道处理的对不对
//            WsConstant.ctxWs.get(ctx).close(ctx.channel(), new CloseWebSocketFrame());

        }
    }
    @Override
    public void onMessage(ByteBuffer bytes) {
        Charset charset = Charset.forName("utf-8");
        CharBuffer charBuffer = charset.decode(bytes);
        String message = charBuffer.toString();
        System.out.println("------ WebSocket onMessage ------[websocket] 收到消息="+message);
        if (ctx != null && ctx.channel() != null && ctx.channel().isActive()) {
            ctx.writeAndFlush(bytebuffer2ByteArray(bytes));
//            ctx.writeAndFlush(new BinaryWebSocketFrame(bytes));
//            ctx.writeAndFlush(bytes);
        }
    }
    public static String byteBufferToString(ByteBuffer buffer) {
        CharBuffer charBuffer = null;
        try {
            Charset charset = Charset.forName("UTF-8");
            CharsetDecoder decoder = charset.newDecoder();
            charBuffer = decoder.decode(buffer);
            buffer.flip();
            return charBuffer.toString();
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }
    public static byte[] bytebuffer2ByteArray(ByteBuffer buffer) {
        //重置 limit 和postion 值
        buffer.flip();
        //获取buffer中有效大小
        int len=buffer.limit() - buffer.position();

        byte [] bytes=new byte[len];

        for (int i = 0; i < bytes.length; i++) {
            bytes[i]=buffer.get();

        }

        return bytes;
    }
//    public static void main(String[] args) {
//        try {
//            MyWebsocketClient myWebsocketClient = new MyWebsocketClient("http://192.168.100.88:7601/demo/websocket", null);
//            myWebsocketClient.connect();
//            while(!myWebsocketClient.getReadyState().equals(ReadyState.OPEN)){
//                System.out.println("还没有打开");
////                myWebsocketClient.close();
//            }
//            System.out.println("打开了");
//            myWebsocketClient.send("111111");
//            Thread.currentThread().join();
//        } catch (URISyntaxException e) {
//            e.printStackTrace();
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
//    }
}