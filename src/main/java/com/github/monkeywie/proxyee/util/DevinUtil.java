package com.github.monkeywie.proxyee.util;

import com.github.monkeywie.proxyee.crt.CertUtilsLoader;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Random;

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

    /**
     * 解码websocket 完整帧消息，返回明文内容
     * @param byteBuf
     * @return
     */
    public static String decodeWebSocketPayload(ByteBuf byteBuf) {
        if (!byteBuf.isReadable()) {
            return "";
        }
        ByteBuf copy = byteBuf.copy();
        byte[] data = hexStringToByteArray(ByteBufUtil.hexDump(copy));
        ByteBuffer buffer = ByteBuffer.wrap(data);
        // 解析第1个字节 (FIN, RSV1-3, OPCODE)
        byte b1 = buffer.get();
        boolean fin = (b1 & 0x80) != 0; // FIN 位
        byte opcode = (byte) (b1 & 0x0F); // OPCODE

        // 解析第2个字节 (MASK, Payload length)
        byte b2 = buffer.get();
        boolean masked = (b2 & 0x80) != 0; // Mask 位
        int payloadLength = b2 & 0x7F; // Payload 长度

        // 如果负载长度为126或127，需要额外读取字节
        if (payloadLength == 126) {
            payloadLength = buffer.getShort();
        } else if (payloadLength == 127) {
            payloadLength = (int) buffer.getLong();
        }

        // 获取 Masking Key
        byte[] mask = null;
        if (masked) {
            mask = new byte[4];
            buffer.get(mask);
        }

        // 读取负载数据
        byte[] payloadData = new byte[payloadLength];
        buffer.get(payloadData);

        // 如果有 Masking Key，进行解码
        if (masked) {
            for (int i = 0; i < payloadData.length; i++) {
                payloadData[i] ^= mask[i % 4]; // 使用 Mask Key 进行解码
            }
        }

        // 将解码后的负载数据转换为字符串
        return new String(payloadData);
    }

    /**
     * 编码websocket 完整帧消息
     * @param message 明文内容
     * @return
     */
    public static ByteBuf encodeWebSocketFrame(String message) {
        byte[] messageBytes = message.getBytes(); // 将消息转换为字节数组
        int messageLength = messageBytes.length;

        // 构建帧头
        ByteBuffer buffer = ByteBuffer.allocate(2 + (messageLength > 125 ? 2 : 0) + 4 + messageLength);
        byte b1 = (byte) 0x81; // FIN=1, OPCODE=0x1 (文本帧)
        buffer.put(b1);

        // 构建帧头第二个字节：Mask=1, Payload Length
        if (messageLength <= 125) {
            buffer.put((byte) (0x80 | messageLength)); // Mask=1, 小于等于125字节
        } else if (messageLength <= 0xFFFF) {
            buffer.put((byte) 0xFE); // Mask=1, 负载长度使用16位
            buffer.putShort((short) messageLength); // 16位的负载长度
        } else {
            throw new IllegalArgumentException("Message is too long");
        }

        // 生成随机 Masking Key
        byte[] mask = new byte[4];
        new Random().nextBytes(mask);
        buffer.put(mask); // 添加 Masking Key

        // 对负载数据进行掩码处理（异或操作）
        for (int i = 0; i < messageBytes.length; i++) {
            messageBytes[i] ^= mask[i % 4]; // 使用 Mask Key 对每个字节进行异或
        }

        // 添加被掩码处理后的负载数据
        buffer.put(messageBytes);

        // 返回完整的 WebSocket 帧
        return Unpooled.wrappedBuffer(buffer.array());
    }

    // 将十六进制字符串转换为字节数组
    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    public boolean isWebSocketFrame(ByteBuf byteBuf) {
        // 标记当前读取位置，便于重置
        byteBuf.markReaderIndex();

        // 确保有足够的数据可读（WebSocket 帧至少有两个字节）
        if (byteBuf.readableBytes() < 2) {
            byteBuf.resetReaderIndex();
            return false;
        }

        // 读取第一个字节
        byte firstByte = byteBuf.readByte();

        // 重置读取位置
        byteBuf.resetReaderIndex();

        // 获取 FIN 位（最高位）
        boolean fin = (firstByte & 0x80) != 0;

        // 获取 Opcode (低4位)
        byte opcode = (byte) (firstByte & 0x0F);

        // WebSocket 帧的 Opcode 应该是以下之一
        if (opcode == 0x1 || // 文本帧
                opcode == 0x2 || // 二进制帧
                opcode == 0x8 || // 关闭帧
                opcode == 0x9 || // Ping 帧
                opcode == 0xA) { // Pong 帧
            return true;
        }

        return false;
    }

}
