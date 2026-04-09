package com.github.monkeywie.proxyee.intercept.cursor;

import com.github.monkeywie.proxyee.connect.ConnectProtoUtil;
import io.netty.buffer.ByteBuf;

import java.util.Arrays;

/**
 * 将任意切片的字节流重组为完整的 gRPC Connect 帧：
 * {@code [1B type][4B BE len][payload]}。
 */
public final class ConnectFrameStreamParser {

    private byte[] buf = new byte[16384];
    private int len;

    public void append(ByteBuf bb) {
        int n = bb.readableBytes();
        ensure(len + n);
        bb.getBytes(bb.readerIndex(), buf, len, n);
        len += n;
    }

    public void append(byte[] data, int off, int datalen) {
        ensure(len + datalen);
        System.arraycopy(data, off, buf, len, datalen);
        len += datalen;
    }

    public int remaining() {
        return len;
    }

    /**
     * 若缓冲区在流结束后仍有残留字节，视为不完整帧。
     */
    public boolean hasIncompleteTrailingData() {
        return len > 0;
    }

    public void clear() {
        len = 0;
    }

    /**
     * @return 完整一帧的 wire 字节（含 5 字节头），或缓冲区不足时返回 null
     */
    public byte[] pollWireFrame() {
        if (len < 5) {
            return null;
        }
        int payloadLen = ((buf[1] & 0xFF) << 24)
                | ((buf[2] & 0xFF) << 16)
                | ((buf[3] & 0xFF) << 8)
                | (buf[4] & 0xFF);
        if (payloadLen < 0 || payloadLen > ConnectProtoUtil.MAX_CONNECT_PAYLOAD_LEN) {
            throw new IllegalStateException("invalid Connect payload length: " + payloadLen);
        }
        int frameLen = 5 + payloadLen;
        if (len < frameLen) {
            return null;
        }
        byte[] frame = Arrays.copyOfRange(buf, 0, frameLen);
        System.arraycopy(buf, frameLen, buf, 0, len - frameLen);
        len -= frameLen;
        return frame;
    }

    private void ensure(int minCapacity) {
        if (buf.length >= minCapacity) {
            return;
        }
        int n = buf.length;
        while (n < minCapacity) {
            n <<= 1;
        }
        buf = Arrays.copyOf(buf, n);
    }

    /**
     * 解析单帧 Connect wire 字节，得到解压后的载荷（若 gzip 失败则为 null）。
     */
    public static final class ParsedConnectFrame {
        public final byte[] wireBytes;
        public final int messageType;
        public final byte[] payloadDecompressed;

        private ParsedConnectFrame(byte[] wireBytes, int messageType, byte[] payloadDecompressed) {
            this.wireBytes = wireBytes;
            this.messageType = messageType;
            this.payloadDecompressed = payloadDecompressed;
        }

        public static ParsedConnectFrame parse(byte[] wire) {
            if (wire == null || wire.length < 5) {
                throw new IllegalArgumentException("wire frame too short");
            }
            int typeByte = wire[0] & 0xFF;
            boolean compressed = (typeByte & 1) != 0;
            int messageType = typeByte >> 1;
            byte[] payload = Arrays.copyOfRange(wire, 5, wire.length);
            byte[] decompressed;
            if (compressed) {
                decompressed = ConnectProtoUtil.gzipDecompress(payload);
            } else {
                decompressed = payload;
            }
            return new ParsedConnectFrame(wire, messageType, decompressed);
        }
    }
}
