package com.github.monkeywie.proxyee.util;

import com.github.monkeywie.proxyee.crt.CertUtilsLoader;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * @version 1.0.0
 * @Author chenqp
 * @Date 2024/9/27
 * @describe
 */
public class DevinUtil {
    private final static InternalLogger log = InternalLoggerFactory.getInstance(DevinUtil.class);

    /**
     * 打印消息
     *
     * @param byteBuf 消息
     * @param pre     打印前缀
     */
    public static void printMsg(ByteBuf byteBuf, String pre) {
        if (!byteBuf.isReadable()) {
            // 消息为空
//            String msg = "消息为空，不打印消息";
//            log.info(msg);
//            System.out.println(msg);
            return;
        }
        ByteBuf copy = byteBuf.copy();
        System.out.println(pre + " 16进制--" + ByteBufUtil.hexDump(copy));
        byte[] bytes = new byte[copy.readableBytes()];
        copy.readBytes(bytes);

        // 将byte数组转换为字符串
        String text = new String(bytes);

        // 输出字符串
        String printText = pre + "：" + text;
        System.out.println(printText);
        log.error(printText);
        // 释放副本
        copy.release();
    }
    public static void printMsg(HttpContent content, String pre) {
        ByteBuf contentBuf = content.content();
        printMsg(contentBuf, pre);
    }
    /**
     * 获取websocket 81消息
     * 文本帧 (0x81): 用于传输 UTF-8 编码的文本数据。
     * 二进制帧 (0x82): 用于传输二进制数据。
     * 关闭帧 (0x88): 表示关闭连接的请求。
     * Ping 帧 (0x89): 用于保持连接活跃。
     * Pong 帧 (0x8A): 对 Ping 帧的回应。
     * @param msg
     * @return
     */
    public static ByteBuf getWebsocketMst81(String msg) {
        byte[] messageBytes = msg.getBytes(StandardCharsets.UTF_8);
        int length = messageBytes.length;

        // 设置帧头，0x81 表示文本帧，length 的 16 进制表示
        ByteBuf prefix = Unpooled.copiedBuffer(new byte[]{(byte) 0x81, (byte) length});
        ByteBuf content = Unpooled.copiedBuffer(messageBytes);
        // 合并前缀和内容
        ByteBuf fullMessage = Unpooled.wrappedBuffer(prefix, content);
        return fullMessage;
    }

    /**
     * 自定义返回JSON响应
     * @param msg
     * @return
     */
    public static FullHttpResponse getFullHttpResponse(String msg) {
        ByteBuf customContentBuf = Unpooled.copiedBuffer(msg, CharsetUtil.UTF_8);

        // 创建完整的 HTTP 响应
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, customContentBuf);
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json; charset=UTF-8");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, customContentBuf.readableBytes());
        return response;
    }
}
