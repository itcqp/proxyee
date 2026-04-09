package com.github.monkeywie.proxyee.connect;

import cn.hutool.core.util.HexUtil;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaders;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 与 {@link com.github.monkeywie.proxyee.CursorChatUtil} 共用的 Cursor {@code StreamUnifiedChatWithTools}
 * protobuf 编码、gRPC Connect 帧封装、设备指纹与 MITM 混合上游头构造。
 */
public final class CursorConnectUpstreamCodec {

    public static final String DEFAULT_MODEL = "claude-3.5-sonnet";

    /** 与当前 Cursor IDE 对齐，避免上游提示版本过旧 */
    public static final String CLIENT_VERSION = "3.0.13";

    private static final int WIRE_TYPE_VARINT = 0;
    private static final int WIRE_TYPE_LENGTH_DELIMITED = 2;

    private static final int MESSAGE_TYPE_HUMAN = 1;
    private static final int MESSAGE_TYPE_AI = 2;
    private static final int UNIFIED_MODE_CHAT = 1;

    private CursorConnectUpstreamCodec() {}

    // ======================== Message（与 CursorChatUtil 一致） ========================

    public static class Message {
        private final String role;
        private final String content;

        public Message(String role, String content) {
            this.role = role;
            this.content = content;
        }

        public String getRole() {
            return role;
        }

        public String getContent() {
            return content;
        }

        public static Message system(String content) {
            return new Message("system", content);
        }

        public static Message user(String content) {
            return new Message("user", content);
        }

        public static Message assistant(String content) {
            return new Message("assistant", content);
        }

        public static List<Message> ofUser(String content) {
            List<Message> messages = new ArrayList<>();
            messages.add(user(content));
            return messages;
        }

        public static List<Message> of(String systemPrompt, String userContent) {
            List<Message> messages = new ArrayList<>();
            if (systemPrompt != null && !systemPrompt.trim().isEmpty()) {
                messages.add(system(systemPrompt));
            }
            messages.add(user(userContent));
            return messages;
        }
    }

    // ======================== DeviceInfo ========================

    public static final class DeviceInfo {
        public final String clientKey;
        final String checksumHash1;
        final String checksumHash2;
        public final String sessionId;

        DeviceInfo(String clientKey, String checksumHash1, String checksumHash2, String sessionId) {
            this.clientKey = clientKey;
            this.checksumHash1 = checksumHash1;
            this.checksumHash2 = checksumHash2;
            this.sessionId = sessionId;
        }

        static DeviceInfo fromToken(String token) {
            String clientKey = HexUtil.encodeHexStr(sha256(token + ":client_key"));
            String hash1 = HexUtil.encodeHexStr(sha256(token + ":checksum_1"));
            String hash2 = HexUtil.encodeHexStr(sha256(token + ":checksum_2"));
            byte[] sidBytes = sha256(token + ":session_id");
            UUID sid =
                    new UUID(bytesToLong(sidBytes, 0), bytesToLong(sidBytes, 8));
            return new DeviceInfo(clientKey, hash1, hash2, sid.toString());
        }

        public String buildChecksum() {
            return generateTimestampHeader() + checksumHash1 + "/" + checksumHash2;
        }

        private static byte[] sha256(String input) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                return md.digest(input.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new RuntimeException("SHA-256 not available", e);
            }
        }

        private static long bytesToLong(byte[] bytes, int offset) {
            long result = 0;
            for (int i = 0; i < 8; i++) {
                result = (result << 8) | (bytes[offset + i] & 0xFFL);
            }
            return result;
        }
    }

    private static final ConcurrentHashMap<String, DeviceInfo> DEVICE_CACHE = new ConcurrentHashMap<>();

    public static DeviceInfo getDeviceInfo(String token) {
        return DEVICE_CACHE.computeIfAbsent(token, DeviceInfo::fromToken);
    }

    /**
     * 单条用户消息的 Connect 帧（与 CursorChatUtil.chatStream 一致：未压缩 protobuf + 5 字节头）。
     */
    public static byte[] buildFramedUnifiedChatBody(String model, String userText) throws IOException {
        byte[] protobufBody = buildChatRequestProtobuf(model, Message.ofUser(userText != null ? userText : ""));
        return wrapGrpcFrame(protobufBody, false);
    }

    public static byte[] buildFramedUnifiedChatBody(String model, String userText, String extraSystemPrompt)
            throws IOException {
        byte[] protobufBody = buildChatRequestProtobuf(
                model,
                Message.of(extraSystemPrompt, userText != null ? userText : ""));
        return wrapGrpcFrame(protobufBody, false);
    }

    /**
     * 构建 StreamUnifiedChatRequestWithTools 外层 protobuf（与 CursorChatUtil 一致）。
     */
    public static byte[] buildChatRequestProtobuf(String model, List<? extends Message> messages) throws IOException {
        StringBuilder systemPrompt = new StringBuilder();
        List<Message> conversationMessages = new ArrayList<>();

        for (Message msg : messages) {
            if ("system".equals(msg.getRole())) {
                if (systemPrompt.length() > 0) {
                    systemPrompt.append("\n\n");
                }
                systemPrompt.append(msg.getContent());
            } else {
                conversationMessages.add(msg);
            }
        }

        if (conversationMessages.isEmpty()) {
            conversationMessages.add(Message.user(""));
        }

        String conversationId = "zmgnb";

        ByteArrayOutputStream requestBuf = new ByteArrayOutputStream(512);
        List<byte[]> headerBytesList = new ArrayList<>(conversationMessages.size());

        for (Message msg : conversationMessages) {
            boolean isUser = "user".equals(msg.getRole());
            String bubbleId = UUID.randomUUID().toString();
            String serverBubbleId = isUser ? null : UUID.randomUUID().toString();

            byte[] convMsg = buildConversationMessage(msg, bubbleId, serverBubbleId);
            writeBytes(requestBuf, 1, convMsg);

            byte[] headerBytes =
                    buildConversationMessageHeader(
                            bubbleId, serverBubbleId, isUser ? MESSAGE_TYPE_HUMAN : MESSAGE_TYPE_AI);
            headerBytesList.add(headerBytes);
        }

        for (byte[] headerBytes : headerBytesList) {
            writeBytes(requestBuf, 30, headerBytes);
        }

        if (systemPrompt.length() > 0) {
            byte[] explicitCtx = buildExplicitContext(systemPrompt.toString());
            writeBytes(requestBuf, 3, explicitCtx);
        }

        byte[] modelDetails = buildModelDetails(model);
        writeBytes(requestBuf, 5, modelDetails);

        writeBool(requestBuf, 13, true);

        byte[] currentFile = buildMinimalCurrentFileInfo();
        writeBytes(requestBuf, 15, currentFile);

        writeBool(requestBuf, 19, true);
        writeBool(requestBuf, 22, true);
        writeString(requestBuf, 23, conversationId);

        byte[] envInfo = buildEnvironmentInfo();
        writeBytes(requestBuf, 26, envInfo);

        writeBool(requestBuf, 37, false);
        writeEnum(requestBuf, 46, UNIFIED_MODE_CHAT);
        writeBool(requestBuf, 48, true);
        writeString(requestBuf, 54, "Ask");

        byte[] streamUnifiedChatRequest = requestBuf.toByteArray();

        ByteArrayOutputStream wrapperBuf = new ByteArrayOutputStream(streamUnifiedChatRequest.length + 10);
        writeBytes(wrapperBuf, 1, streamUnifiedChatRequest);

        return wrapperBuf.toByteArray();
    }

    public static byte[] wrapGrpcFrame(byte[] data, boolean compressed) {
        byte[] frame = new byte[5 + data.length];
        frame[0] = compressed ? (byte) 1 : (byte) 0;
        frame[1] = (byte) ((data.length >> 24) & 0xFF);
        frame[2] = (byte) ((data.length >> 16) & 0xFF);
        frame[3] = (byte) ((data.length >> 8) & 0xFF);
        frame[4] = (byte) (data.length & 0xFF);
        System.arraycopy(data, 0, frame, 5, data.length);
        return frame;
    }

    /**
     * MITM RunSSE→UnifiedChat：混合上游头（透传 session/request/trace，其余按 chatStream + DeviceInfo）。
     */
    public static HttpHeaders hybridUpstreamHeadersForUnifiedChat(HttpHeaders client, String bearerToken) {
        DeviceInfo device = getDeviceInfo(bearerToken);
        String checksum = device.buildChecksum();

        String sessionFromClient = headerFirst(client, "x-session-id");
        String requestFromClient = headerFirst(client, "x-request-id");
        String sessionId = (sessionFromClient != null && !sessionFromClient.isEmpty()) ? sessionFromClient : device.sessionId;
        String requestId =
                (requestFromClient != null && !requestFromClient.isEmpty())
                        ? requestFromClient
                        : UUID.randomUUID().toString();

        DefaultHttpHeaders h = new DefaultHttpHeaders();
        h.set("Authorization", "Bearer " + bearerToken);
        h.set("connect-accept-encoding", "gzip");
        h.set("connect-content-encoding", "gzip");
        h.set("connect-protocol-version", "1");
        h.set("User-Agent", "connect-es/1.6.1");
        h.set("x-amzn-trace-id", "Root=" + requestId);
        h.set("x-client-key", device.clientKey);
        h.set("x-cursor-checksum", checksum);
        h.set("x-cursor-client-version", CLIENT_VERSION);
        h.set("x-cursor-streaming", "true");
        h.set("x-cursor-timezone", "Asia/Shanghai");
        h.set("x-ghost-mode", "true");
        h.set("x-new-onboarding-completed", "false");
        h.set("x-request-id", requestId);
        h.set("x-session-id", sessionId);
        h.set("Cookie", "");

        String tp = headerFirst(client, "traceparent");
        if (tp != null && !tp.isEmpty()) {
            h.set("traceparent", tp);
        }
        String ct = headerFirst(client, "content-type");
        if (ct == null || ct.isEmpty()) {
            ct = "application/connect+proto";
        }
        h.set("Content-Type", ct);
        return h;
    }

    private static String headerFirst(HttpHeaders client, String name) {
        if (client == null) {
            return null;
        }
        String v = client.get(name);
        if (v != null && !v.isEmpty()) {
            return v;
        }
        for (String n : client.names()) {
            if (n != null && n.equalsIgnoreCase(name)) {
                return client.get(n);
            }
        }
        return null;
    }

    /**
     * 从 {@code Authorization: Bearer ...} 解析裸 JWT，失败返回 null。
     */
    public static String parseBearerToken(HttpHeaders headers) {
        if (headers == null) {
            return null;
        }
        String auth = headerFirst(headers, "Authorization");
        if (auth == null) {
            return null;
        }
        String a = auth.trim();
        if (a.length() > 7 && a.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return a.substring(7).trim();
        }
        return null;
    }

    private static byte[] buildConversationMessage(Message msg, String bubbleId, String serverBubbleId)
            throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(256);
        writeString(buf, 1, msg.getContent());
        boolean isUser = "user".equals(msg.getRole());
        writeEnum(buf, 2, isUser ? MESSAGE_TYPE_HUMAN : MESSAGE_TYPE_AI);
        writeString(buf, 13, bubbleId);
        if (serverBubbleId != null) {
            writeString(buf, 32, serverBubbleId);
        }
        writeEnum(buf, 47, UNIFIED_MODE_CHAT);
        return buf.toByteArray();
    }

    private static byte[] buildConversationMessageHeader(String bubbleId, String serverBubbleId, int type)
            throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        writeString(buf, 1, bubbleId);
        if (serverBubbleId != null) {
            writeString(buf, 2, serverBubbleId);
        }
        writeEnum(buf, 3, type);
        return buf.toByteArray();
    }

    private static byte[] buildExplicitContext(String instructions) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(instructions.length() + 10);
        writeString(buf, 1, instructions);
        return buf.toByteArray();
    }

    private static byte[] buildModelDetails(String model) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        writeString(buf, 1, model);
        writeBytes(buf, 4, new byte[0]);
        return buf.toByteArray();
    }

    private static byte[] buildMinimalCurrentFileInfo() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(32);
        writeBytes(buf, 3, new byte[0]);
        ByteArrayOutputStream rangeBuf = new ByteArrayOutputStream(8);
        writeBytes(rangeBuf, 1, new byte[0]);
        writeBytes(rangeBuf, 2, new byte[0]);
        writeBytes(buf, 6, rangeBuf.toByteArray());
        writeInt32(buf, 8, 1);
        writeInt32(buf, 9, 1);
        return buf.toByteArray();
    }

    private static byte[] buildEnvironmentInfo() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        writeString(buf, 1, "win32");
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        writeString(buf, 5, timestamp);
        short[] vp = parseSemverParts(CLIENT_VERSION);
        byte[] versionBytes = new byte[6];
        ByteBuffer.wrap(versionBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putShort(vp[0])
                .putShort(vp[1])
                .putShort(vp[2]);
        writeBytesField(buf, 7, versionBytes);
        return buf.toByteArray();
    }

    private static short[] parseSemverParts(String v) {
        if (v == null || v.isEmpty()) {
            return new short[] {2, 4, 28};
        }
        String[] p = v.split("\\.");
        int major = p.length > 0 ? parseIntSafe(p[0], 2) : 2;
        int minor = p.length > 1 ? parseIntSafe(p[1], 4) : 4;
        int patch = p.length > 2 ? parseIntSafe(p[2], 28) : 28;
        return new short[] {(short) major, (short) minor, (short) patch};
    }

    private static int parseIntSafe(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static void writeVarint(ByteArrayOutputStream os, int value) throws IOException {
        long v = value & 0xFFFFFFFFL;
        while (v > 0x7F) {
            os.write((int) (v & 0x7F) | 0x80);
            v >>>= 7;
        }
        os.write((int) v);
    }

    private static void writeTag(ByteArrayOutputStream os, int fieldNumber, int wireType) throws IOException {
        writeVarint(os, (fieldNumber << 3) | wireType);
    }

    private static void writeString(ByteArrayOutputStream os, int fieldNumber, String value) throws IOException {
        if (value == null || value.isEmpty()) {
            writeTag(os, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
            writeVarint(os, 0);
            return;
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeTag(os, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
        writeVarint(os, bytes.length);
        os.write(bytes);
    }

    private static void writeBytes(ByteArrayOutputStream os, int fieldNumber, byte[] data) throws IOException {
        writeTag(os, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
        writeVarint(os, data.length);
        os.write(data);
    }

    private static void writeBytesField(ByteArrayOutputStream os, int fieldNumber, byte[] data) throws IOException {
        writeTag(os, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
        writeVarint(os, data.length);
        os.write(data);
    }

    private static void writeBool(ByteArrayOutputStream os, int fieldNumber, boolean value) throws IOException {
        if (!value) {
            writeTag(os, fieldNumber, WIRE_TYPE_VARINT);
            writeVarint(os, 0);
            return;
        }
        writeTag(os, fieldNumber, WIRE_TYPE_VARINT);
        writeVarint(os, 1);
    }

    private static void writeInt32(ByteArrayOutputStream os, int fieldNumber, int value) throws IOException {
        writeTag(os, fieldNumber, WIRE_TYPE_VARINT);
        writeVarint(os, value);
    }

    private static void writeEnum(ByteArrayOutputStream os, int fieldNumber, int value) throws IOException {
        writeTag(os, fieldNumber, WIRE_TYPE_VARINT);
        writeVarint(os, value);
    }

    private static String generateTimestampHeader() {
        long now = System.currentTimeMillis() / 1000;
        long timeKs = now / 1000;
        byte[] timeBytes = new byte[4];
        timeBytes[0] = (byte) ((timeKs >> 24) & 0xFF);
        timeBytes[1] = (byte) ((timeKs >> 16) & 0xFF);
        timeBytes[2] = (byte) ((timeKs >> 8) & 0xFF);
        timeBytes[3] = (byte) (timeKs & 0xFF);
        byte[] raw = new byte[6];
        raw[0] = timeBytes[2];
        raw[1] = timeBytes[3];
        raw[2] = timeBytes[0];
        raw[3] = timeBytes[1];
        raw[4] = timeBytes[2];
        raw[5] = timeBytes[3];
        byte prev = (byte) 165;
        for (int i = 0; i < raw.length; i++) {
            byte original = raw[i];
            raw[i] = (byte) ((original ^ prev) + (i % 256));
            prev = raw[i];
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }
}
