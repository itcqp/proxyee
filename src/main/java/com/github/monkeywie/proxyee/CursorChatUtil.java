package com.github.monkeywie.proxyee;

import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.jwt.JWT;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;

import java.io.*;
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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.zip.GZIPInputStream;

/**
 * Cursor AI 原生 API 消息发送工具类
 * <p>
 * 直接调用 Cursor 原生 API（api2.cursor.sh），使用 protobuf + gRPC Connect 流式协议。
 * 无需部署任何代理服务，直接使用 Cursor Token 发送消息。
 * <p>
 * 使用示例：
 * <pre>
 * // 1. 最简单 - 直接发消息
 * String reply = CursorChatUtil.chat("your-cursor-token", "你好，请介绍一下自己");
 *
 * // 2. 指定模型
 * String reply = CursorChatUtil.chat("your-cursor-token", "claude-3.5-sonnet", "你好");
 *
 * // 3. 多轮对话
 * List&lt;CursorChatUtil.Message&gt; messages = new ArrayList&lt;&gt;();
 * messages.add(CursorChatUtil.Message.system("你是一个Java专家"));
 * messages.add(CursorChatUtil.Message.user("帮我写一个单例模式"));
 * String reply = CursorChatUtil.chat("your-cursor-token", "claude-3.5-sonnet", messages);
 *
 * // 4. 流式调用（逐字输出）
 * CursorChatUtil.chatStream("your-cursor-token", "你好", chunk -> System.out.print(chunk));
 * </pre>
 *
 * @author cqp
 */
@Slf4j
public class CursorChatUtil {

    // ======================== 常量 ========================

    /** Cursor API 地址 */
    private static final String CURSOR_API_URL = "https://api2.cursor.sh/aiserver.v1.ChatService/StreamUnifiedChatWithTools";

    /** 默认模型 */
    private static final String DEFAULT_MODEL = "claude-3.5-sonnet";

    /** 默认客户端版本（参照 cursor-api-main 的 header/version.rs DEFAULT_CLIENT_VERSION） */
    private static final String CLIENT_VERSION = "2.4.28";

    /** 默认超时时间（毫秒） */
    private static final int DEFAULT_TIMEOUT = 120_000;

    // ======================== Protobuf 常量 ========================

    /** Protobuf wire type: Varint */
    private static final int WIRE_TYPE_VARINT = 0;
    /** Protobuf wire type: Length-delimited */
    private static final int WIRE_TYPE_LENGTH_DELIMITED = 2;

    /** ConversationMessage.MessageType: Human */
    private static final int MESSAGE_TYPE_HUMAN = 1;
    /** ConversationMessage.MessageType: AI */
    private static final int MESSAGE_TYPE_AI = 2;

    /** StreamUnifiedChatRequest.UnifiedMode: Chat */
    private static final int UNIFIED_MODE_CHAT = 1;
    private static final int UNIFIED_MODE_AGENT = 2;
    // ======================== 设备指纹（防止每次变化被锁号） ========================

    /**
     * 设备指纹信息，同一个 token 始终使用同一组值。
     * 参照 cursor-api-main 的 ExtToken 结构体：checksum / client_key / session_id 都是绑定 token 固定不变的。
     */
    private static class DeviceInfo {
        final String clientKey;       // x-client-key: 64位hex (32字节)
        final String checksumHash1;   // checksum 第一段: 设备hash 64位hex
        final String checksumHash2;   // checksum 第二段: MAC hash 64位hex
        final String sessionId;       // x-session-id: UUID

        DeviceInfo(String clientKey, String checksumHash1, String checksumHash2, String sessionId) {
            this.clientKey = clientKey;
            this.checksumHash1 = checksumHash1;
            this.checksumHash2 = checksumHash2;
            this.sessionId = sessionId;
        }

        /**
         * 从 token 确定性地派生设备指纹。
         * 使用 SHA-256(token + salt) 保证：同一 token 永远得到同一组设备标识。
         */
        static DeviceInfo fromToken(String token) {
            JWT jwt = JWT.of(token);
            Object sub = jwt.getPayload("sub");
            String uid = sub.toString().replace("auth0|", "");
            String mail =uid;

            String clientKey = HexUtil.encodeHexStr(sha256(token + ":client_key"));
            String hash1 = HexUtil.encodeHexStr(sha256(token + ":checksum_1"));
            String hash2 = HexUtil.encodeHexStr(sha256(token + ":checksum_2"));
            // 用前16字节构造 UUID
            byte[] sidBytes = sha256(token + ":session_id");
            UUID sid = new UUID(
                    bytesToLong(sidBytes, 0),
                    bytesToLong(sidBytes, 8)
            );
            return new DeviceInfo(clientKey, hash1, hash2, sid.toString());
        }

        /** 生成完整 checksum（时间戳部分每次更新，hash 部分固定） */
        String buildChecksum() {
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

    /** 设备指纹缓存：token -> DeviceInfo，同一 token 始终复用同一设备 */
    private static final ConcurrentHashMap<String, DeviceInfo> DEVICE_CACHE = new ConcurrentHashMap<>();

    /** 获取或创建 token 对应的设备指纹 */
    private static DeviceInfo getDeviceInfo(String token) {
        return DEVICE_CACHE.computeIfAbsent(token, DeviceInfo::fromToken);
    }

    // ======================== 消息对象 ========================

    /**
     * 聊天消息
     */
    public static class Message {
        private final String role;
        private final String content;

        public Message(String role, String content) {
            this.role = role;
            this.content = content;
        }

        public String getRole() { return role; }
        public String getContent() { return content; }

        /** 创建系统消息 */
        public static Message system(String content) {
            return new Message("system", content);
        }

        /** 创建用户消息 */
        public static Message user(String content) {
            return new Message("user", content);
        }

        /** 创建助手消息 */
        public static Message assistant(String content) {
            return new Message("assistant", content);
        }

        /** 快捷方法：创建仅包含一条用户消息的列表 */
        public static List<Message> ofUser(String content) {
            List<Message> messages = new ArrayList<>();
            messages.add(user(content));
            return messages;
        }

        /** 快捷方法：创建包含系统提示和用户消息的列表 */
        public static List<Message> of(String systemPrompt, String userContent) {
            List<Message> messages = new ArrayList<>();
            if (StrUtil.isNotBlank(systemPrompt)) {
                messages.add(system(systemPrompt));
            }
            messages.add(user(userContent));
            return messages;
        }
    }

    // ======================== 对外 API ========================

    /**
     * 发送消息（最简单的调用方式）
     *
     * @param token   Cursor 的 AccessToken (JWT)
     * @param content 用户消息内容
     * @return AI 回复内容，失败返回 null
     */
    public static String chat(String token, String content) {
        return chat(token, DEFAULT_MODEL, Message.ofUser(content));
    }

    /**
     * 发送消息（指定模型）
     *
     * @param token   Cursor 的 AccessToken (JWT)
     * @param model   模型名称，如 "claude-3.5-sonnet"、"gpt-4o" 等
     * @param content 用户消息内容
     * @return AI 回复内容，失败返回 null
     */
    public static String chat(String token, String model, String content) {
        return chat(token, model, Message.ofUser(content));
    }

    /**
     * 发送消息（多轮对话）
     *
     * @param token    Cursor 的 AccessToken (JWT)
     * @param model    模型名称
     * @param messages 消息列表
     * @return AI 回复内容，失败返回 null
     */
    public static String chat(String token, String model, List<Message> messages) {
        StringBuilder sb = new StringBuilder();
        boolean success = chatStream(token, model, messages, sb::append);
        return success ? sb.toString() : null;
    }

    /**
     * 流式发送消息（最简单的调用方式）
     *
     * @param token         Cursor 的 AccessToken (JWT)
     * @param content       用户消息内容
     * @param chunkConsumer 逐块回调
     * @return 是否成功
     */
    public static boolean chatStream(String token, String content, Consumer<String> chunkConsumer) {
        return chatStream(token, DEFAULT_MODEL, Message.ofUser(content), chunkConsumer);
    }

    /**
     * 流式发送消息（完整参数）
     *
     * @param token         Cursor 的 AccessToken (JWT)
     * @param model         模型名称
     * @param messages      消息列表
     * @param chunkConsumer 逐块回调，每收到一段内容文本就调用
     * @return 是否成功
     */
    /** OkHttp 客户端（复用连接池，HTTPS 默认 HTTP/2 via ALPN） */
    private static final OkHttpClient OK_CLIENT = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(DEFAULT_TIMEOUT, TimeUnit.MILLISECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();

    private static final MediaType CONNECT_PROTO = MediaType.parse("application/connect+proto");

    public static boolean chatStream(String token, String model, List<Message> messages, Consumer<String> chunkConsumer) {
        try {
            // 1. 构建 protobuf 请求体
            byte[] protobufBody = buildChatRequestProtobuf(model, messages);

            // 2. 包装为 gRPC Connect 帧（不压缩）
            byte[] framedBody = wrapGrpcFrame(protobufBody, false);

            // 3. 获取设备指纹（同一 token 固定不变，防止锁号）
            DeviceInfo device = getDeviceInfo(token);
            String requestId = UUID.randomUUID().toString(); // 每次请求不同（正常行为）
            String checksum = device.buildChecksum(); // hash固定，只有时间戳前缀更新

            log.info("Cursor API 请求: model={}, bodyLen={}", model, framedBody.length);

            // 4. 使用 OkHttp 发送 HTTP/2 请求（OkHttp 3.x 纯Java，HTTPS默认HTTP/2）
            //    参照 cursor-api-main/src/common/client.rs build_client_request()
            Request request = new Request.Builder()
                    .url(CURSOR_API_URL)
                    .post(RequestBody.create(CONNECT_PROTO, framedBody))
                    .header("Authorization", "Bearer " + token)
                    .header("connect-accept-encoding", "gzip")
                    .header("connect-content-encoding", "gzip")
                    .header("connect-protocol-version", "1")
                    .header("User-Agent", "connect-es/1.6.1")
                    .header("x-amzn-trace-id", "Root=" + requestId)
                    .header("x-client-key", device.clientKey)
                    .header("x-cursor-checksum", checksum)
                    .header("x-cursor-client-version", CLIENT_VERSION)
                    .header("x-cursor-streaming", "true")
                    .header("x-cursor-timezone", "Asia/Shanghai")
                    .header("x-ghost-mode", "true")
                    .header("x-new-onboarding-completed", "false")
                    .header("x-request-id", requestId)
                    .header("x-session-id", device.sessionId)
//                    .header("x-session-id", "zmg66")
                    .header("Cookie", "")
                    .build();

            try (Response response = OK_CLIENT.newCall(request).execute()) {
                int statusCode = response.code();
                log.info("Cursor API 响应: status={}, protocol={}", statusCode, response.protocol());

                ResponseBody body = response.body();
                if (statusCode != 200) {
                    byte[] rawBytes = body != null ? body.bytes() : new byte[0];
                    String errorBody = parseErrorBody(rawBytes);
                    log.error("Cursor API 请求失败: status={}, protocol={}, body={}",
                            statusCode, response.protocol(), errorBody);
                    return false;
                }

                if (body == null) {
                    log.error("Cursor API 响应体为空");
                    return false;
                }

                // 5. 解析流式响应
                return parseStreamResponse(body.byteStream(), chunkConsumer);
            }

        } catch (Exception e) {
            log.error("Cursor API 请求异常", e);
            return false;
        }
    }
    public static Call createChatStreamCall(String token, String model, List<Message> messages) throws IOException {
        // 1. 构建请求（和原来一模一样）
        byte[] protobufBody = buildChatRequestProtobuf(model, messages);
        byte[] framedBody = wrapGrpcFrame(protobufBody, false);
        DeviceInfo device = getDeviceInfo(token);
        String requestId = UUID.randomUUID().toString();
        String checksum = device.buildChecksum();

        Request request = new Request.Builder()
                .url(CURSOR_API_URL)
                .post(RequestBody.create(CONNECT_PROTO, framedBody))
                .header("Authorization", "Bearer " + token)
                .header("connect-accept-encoding", "gzip")
                .header("connect-content-encoding", "gzip")
                .header("connect-protocol-version", "1")
                .header("User-Agent", "connect-es/1.6.1")
                .header("x-amzn-trace-id", "Root=" + requestId)
                .header("x-client-key", device.clientKey)
                .header("x-cursor-checksum", checksum)
                .header("x-cursor-client-version", CLIENT_VERSION)
                .header("x-cursor-streaming", "true")
//                .header("x-cursor-timezone", "Asia/Shanghai")
                .header("x-cursor-timezone", "America/New_York")
                .header("x-ghost-mode", "true")
                .header("x-new-onboarding-completed", "false")
                .header("x-request-id", requestId)
                .header("x-session-id", device.sessionId)
//                    .header("x-session-id", "zmg66")
                .header("Cookie", "")
                .build();
        System.out.println("checksum："+checksum);
        // 2. 创建 Call 但不执行
        return OK_CLIENT.newCall(request); // ✅ 只返回 Call 对象
    }
    // ======================== Protobuf 编码 ========================

    /**
     * 构建 StreamUnifiedChatRequestWithTools 的 protobuf 二进制数据
     *
     * 消息结构（参照 lite.proto）：
     * StreamUnifiedChatRequestWithTools {
     *   field 1: StreamUnifiedChatRequest { ... }
     * }
     */
    private static byte[] buildChatRequestProtobuf(String model, List<Message> messages) throws IOException {
        // 分离 system 消息和对话消息
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

        // 如果没有对话消息，添加一个空的用户消息
        if (conversationMessages.isEmpty()) {
            conversationMessages.add(Message.user(""));
        }

//        String conversationId = UUID.randomUUID().toString();
        String conversationId = "zmgnb";

        // 构建 StreamUnifiedChatRequest
        ByteArrayOutputStream requestBuf = new ByteArrayOutputStream(512);
        List<byte[]> headerBytesList = new ArrayList<>(conversationMessages.size());

        // field 1: repeated ConversationMessage conversation
        // field 30: repeated ConversationMessageHeader full_conversation_headers_only（每条消息对应一个 header）
        for (Message msg : conversationMessages) {
            boolean isUser = "user".equals(msg.getRole());
            String bubbleId = UUID.randomUUID().toString();
            String serverBubbleId = isUser ? null : UUID.randomUUID().toString();

            byte[] convMsg = buildConversationMessage(msg, bubbleId, serverBubbleId);
            writeBytes(requestBuf, 1, convMsg);

            byte[] headerBytes = buildConversationMessageHeader(bubbleId, serverBubbleId, isUser ? MESSAGE_TYPE_HUMAN : MESSAGE_TYPE_AI);
            headerBytesList.add(headerBytes);
        }

        // field 30: full_conversation_headers_only
        for (byte[] headerBytes : headerBytesList) {
            writeBytes(requestBuf, 30, headerBytes);
        }

        // field 3: ExplicitContext explicit_context（系统指令）
        if (systemPrompt.length() > 0) {
            byte[] explicitCtx = buildExplicitContext(systemPrompt.toString());
            writeBytes(requestBuf, 3, explicitCtx);
        }

        // field 5: ModelDetails model_details
        byte[] modelDetails = buildModelDetails(model);
        writeBytes(requestBuf, 5, modelDetails);

        // field 13: should_cache = true
        writeBool(requestBuf, 13, true);

        // field 15: CurrentFileInfo current_file（最小化的文件信息）
        byte[] currentFile = buildMinimalCurrentFileInfo();
        writeBytes(requestBuf, 15, currentFile);

        // field 19: use_new_compression_scheme = true
        writeBool(requestBuf, 19, true);

        // field 22: is_chat = true
        writeBool(requestBuf, 22, true);

        // field 23: conversation_id
        writeString(requestBuf, 23, conversationId);

        // field 26: EnvironmentInfo environment_info
        byte[] envInfo = buildEnvironmentInfo();
        writeBytes(requestBuf, 26, envInfo);

        // field 27: is_agentic = false (protobuf默认值，不写入)
        writeBool(requestBuf, 27, true);
        // field 37: allow_model_fallbacks = false
        writeBool(requestBuf, 37, false);

        // field 46: unified_mode = UNIFIED_MODE_AGENT (1)
        writeEnum(requestBuf, 46, UNIFIED_MODE_AGENT);

        // field 48: should_disable_tools = true
        writeBool(requestBuf, 48, false);

        // field 49: thinking_level = THINKING_LEVEL_UNSPECIFIED (0) (protobuf默认值，不写入)

        // field 51: uses_rules = false (protobuf默认值，不写入)

        // field 54: unified_mode_name = "Aagent"
        writeString(requestBuf, 54, "Agent");

        byte[] streamUnifiedChatRequest = requestBuf.toByteArray();

        // 包装为 StreamUnifiedChatRequestWithTools
        // field 1: StreamUnifiedChatRequest (oneof request)
        ByteArrayOutputStream wrapperBuf = new ByteArrayOutputStream(streamUnifiedChatRequest.length + 10);
        writeBytes(wrapperBuf, 1, streamUnifiedChatRequest);

        return wrapperBuf.toByteArray();
    }

    /**
     * 构建 ConversationMessage protobuf
     *
     * ConversationMessage {
     *   field 1: string text
     *   field 2: MessageType type (1=Human, 2=AI)
     *   field 13: string bubble_id (UUID)
     *   field 32: optional string server_bubble_id (for AI)
     *   field 47: optional UnifiedMode unified_mode
     * }
     */
    private static byte[] buildConversationMessage(Message msg, String bubbleId, String serverBubbleId) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(256);

        // field 1: text
        writeString(buf, 1, msg.getContent());

        // field 2: type
        boolean isUser = "user".equals(msg.getRole());
        writeEnum(buf, 2, isUser ? MESSAGE_TYPE_HUMAN : MESSAGE_TYPE_AI);

        // field 13: bubble_id
        writeString(buf, 13, bubbleId);

        // field 32: server_bubble_id（仅 AI 消息）
        if (serverBubbleId != null) {
            writeString(buf, 32, serverBubbleId);
        }

        // field 47: unified_mode = Chat
        writeEnum(buf, 47, UNIFIED_MODE_AGENT);

        return buf.toByteArray();
    }

    /**
     * 构建 ConversationMessageHeader protobuf（用于 field 30 full_conversation_headers_only）
     *
     * ConversationMessageHeader {
     *   field 1: string bubble_id
     *   field 2: optional string server_bubble_id（AI 消息）
     *   field 3: MessageType type (1=Human, 2=AI)
     * }
     */
    private static byte[] buildConversationMessageHeader(String bubbleId, String serverBubbleId, int type) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        writeString(buf, 1, bubbleId);
        if (serverBubbleId != null) {
            writeString(buf, 2, serverBubbleId);
        }
        writeEnum(buf, 3, type);
        return buf.toByteArray();
    }

    /**
     * 构建 ExplicitContext protobuf
     *
     * ExplicitContext {
     *   field 1: string context
     * }
     */
    private static byte[] buildExplicitContext(String instructions) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(instructions.length() + 10);
        writeString(buf, 1, instructions);
        return buf.toByteArray();
    }

    /**
     * 构建 ModelDetails protobuf
     *
     * ModelDetails {
     *   field 1: optional string model_name
     *   field 4: optional AzureState azure_state (empty message)
     * }
     */
    private static byte[] buildModelDetails(String model) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        writeString(buf, 1, model);
        // field 4: AzureState (empty sub-message)
        writeBytes(buf, 4, new byte[0]);
        return buf.toByteArray();
    }

    /**
     * 构建最小化的 CurrentFileInfo protobuf
     *
     * CurrentFileInfo {
     *   field 3: CursorPosition cursor_position (default)
     *   field 6: CursorRange selection (default)
     *   field 8: int32 total_number_of_lines = 1
     *   field 9: int32 contents_start_at_line = 1
     * }
     */
    private static byte[] buildMinimalCurrentFileInfo() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(32);
        // field 3: CursorPosition (empty = default 0,0)
        writeBytes(buf, 3, new byte[0]);
        // field 6: CursorRange selection (contains two empty CursorPositions)
        ByteArrayOutputStream rangeBuf = new ByteArrayOutputStream(8);
        writeBytes(rangeBuf, 1, new byte[0]); // start_position
        writeBytes(rangeBuf, 2, new byte[0]); // end_position
        writeBytes(buf, 6, rangeBuf.toByteArray());
        // field 8: total_number_of_lines = 1
        writeInt32(buf, 8, 1);
        // field 9: contents_start_at_line = 1
        writeInt32(buf, 9, 1);
        return buf.toByteArray();
    }

    /**
     * 构建 EnvironmentInfo protobuf
     *
     * EnvironmentInfo {
     *   field 1: optional string exthost_platform
     *   field 5: string local_timestamp
     *   field 7: bytes cursor_version
     * }
     */
    private static byte[] buildEnvironmentInfo() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        // field 1: exthost_platform
        writeString(buf, 1, "win32");
        // field 5: local_timestamp
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        writeString(buf, 5, timestamp);
        // field 7: cursor_version (版本号的字节表示)
        // 版本格式: major.minor.patch -> 3个 uint16 小端序 (参照 cursor_version.rs Version::to_bytes)
        // 与 CLIENT_VERSION 对应
        byte[] versionBytes = new byte[6];
        ByteBuffer.wrap(versionBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 2)   // major = 2
                .putShort((short) 4)   // minor = 4
                .putShort((short) 28); // patch = 28
        writeBytesField(buf, 7, versionBytes);
        return buf.toByteArray();
    }

    // ======================== gRPC Connect 帧编码 ========================

    /**
     * 包装 protobuf 数据为 gRPC Connect 帧格式
     *
     * 帧格式:
     * [1B 压缩标志] [4B 大端序长度] [数据]
     *
     * @param data       protobuf 数据
     * @param compressed 是否已压缩
     * @return 帧数据
     */
    private static byte[] wrapGrpcFrame(byte[] data, boolean compressed) {
        byte[] frame = new byte[5 + data.length];
        frame[0] = compressed ? (byte) 1 : (byte) 0;
        // 大端序写入长度
        frame[1] = (byte) ((data.length >> 24) & 0xFF);
        frame[2] = (byte) ((data.length >> 16) & 0xFF);
        frame[3] = (byte) ((data.length >> 8) & 0xFF);
        frame[4] = (byte) (data.length & 0xFF);
        System.arraycopy(data, 0, frame, 5, data.length);
        return frame;
    }

    // ======================== 响应解析 ========================

    /**
     * 解析 gRPC Connect 流式响应
     *
     * 响应是连续的帧：
     * [1B type] [4B 大端序长度] [数据]
     *
     * type 低位: 0=未压缩, 1=gzip压缩
     * type 高位 (>>1): 0=protobuf消息, 1=JSON消息（错误/结束）
     */
    private static boolean parseStreamResponse(InputStream inputStream, Consumer<String> chunkConsumer) {
        try (DataInputStream dis = new DataInputStream(new BufferedInputStream(inputStream))) {
            while (true) {
                // 读取帧头
                int typeByte;
                try {
                    typeByte = dis.readUnsignedByte();
                } catch (EOFException e) {
                    // 流正常结束
                    break;
                }

                // 读取长度
                int length = dis.readInt(); // 大端序 4 字节
                if (length < 0 || length > 4 * 1024 * 1024) {
                    log.error("无效的帧长度: {}", length);
                    return false;
                }

                // 读取数据
                byte[] data = new byte[length];
                dis.readFully(data);

                // 判断是否压缩
                boolean isCompressed = (typeByte & 1) != 0;
                int messageType = typeByte >> 1;

                // 解压缩
                if (isCompressed) {
                    data = gzipDecompress(data);
                    if (data == null) {
                        log.error("gzip 解压失败");
                        continue;
                    }
                }

                if (messageType == 0) {
                    // Protobuf 消息: StreamUnifiedChatResponseWithTools
                    String text = extractTextFromResponse(data);
                    if (text != null && !text.isEmpty()) {
                        if (chunkConsumer != null) {
                            chunkConsumer.accept(text);
                        }
                    }
                } else if (messageType == 1) {
                    // JSON 消息
                    if (length <= 2) {
                        // 流结束标记
                        break;
                    } else {
                        // 错误消息
                        String errorJson = new String(data, StandardCharsets.UTF_8);
                        log.error("Cursor 返回错误: {}", errorJson);
                        return false;
                    }
                }
            }
            return true;
        } catch (EOFException e) {
            // 正常结束
            return true;
        } catch (Exception e) {
            log.error("解析流式响应异常", e);
            return false;
        }
    }

    /**
     * 从 StreamUnifiedChatResponseWithTools protobuf 中提取文本
     *
     * StreamUnifiedChatResponseWithTools {
     *   field 2: StreamUnifiedChatResponse {  // oneof response
     *     field 1: string text
     *   }
     * }
     *
     * 也处理 field 1: ClientSideToolV2Call（忽略）
     */
    private static String extractTextFromResponse(byte[] data) {
        try {
            int pos = 0;
            while (pos < data.length) {
                int[] tagResult = readTag(data, pos);
                int fieldNumber = tagResult[0];
                int wireType = tagResult[1];
                pos = tagResult[2];

                if (wireType == WIRE_TYPE_LENGTH_DELIMITED) {
                    int[] lenResult = readVarint(data, pos);
                    int len = lenResult[0];
                    pos = lenResult[1];

                    if (fieldNumber == 2) {
                        // StreamUnifiedChatResponse - 提取其中的 text 字段
                        return extractTextField(data, pos, len);
                    }

                    // 跳过其他字段
                    pos += len;
                } else if (wireType == WIRE_TYPE_VARINT) {
                    int[] varintResult = readVarint(data, pos);
                    pos = varintResult[1];
                } else {
                    // 跳过其他 wire type
                    break;
                }
            }
        } catch (Exception e) {
            log.debug("解析 protobuf 响应失败", e);
        }
        return null;
    }

    /**
     * 从 StreamUnifiedChatResponse 子消息中提取 text 字段
     *
     * StreamUnifiedChatResponse {
     *   field 1: string text
     * }
     */
    private static String extractTextField(byte[] data, int offset, int length) {
        try {
            int pos = offset;
            int end = offset + length;
            while (pos < end) {
                int[] tagResult = readTag(data, pos);
                int fieldNumber = tagResult[0];
                int wireType = tagResult[1];
                pos = tagResult[2];

                if (wireType == WIRE_TYPE_LENGTH_DELIMITED) {
                    int[] lenResult = readVarint(data, pos);
                    int len = lenResult[0];
                    pos = lenResult[1];

                    if (fieldNumber == 1) {
                        // text 字段
                        return new String(data, pos, len, StandardCharsets.UTF_8);
                    }

                    pos += len;
                } else if (wireType == WIRE_TYPE_VARINT) {
                    int[] varintResult = readVarint(data, pos);
                    pos = varintResult[1];
                } else if (wireType == 1) { // 64-bit
                    pos += 8;
                } else if (wireType == 5) { // 32-bit
                    pos += 4;
                } else {
                    break;
                }
            }
        } catch (Exception e) {
            log.debug("解析 text 字段失败", e);
        }
        return null;
    }

    // ======================== Protobuf 底层编码工具 ========================

    /** 写入 varint 编码 */
    private static void writeVarint(OutputStream os, int value) throws IOException {
        // 处理负数（使用 unsigned 编码）
        long v = value & 0xFFFFFFFFL;
        while (v > 0x7F) {
            os.write((int) (v & 0x7F) | 0x80);
            v >>>= 7;
        }
        os.write((int) v);
    }

    /** 写入 tag (fieldNumber + wireType) */
    private static void writeTag(OutputStream os, int fieldNumber, int wireType) throws IOException {
        writeVarint(os, (fieldNumber << 3) | wireType);
    }

    /** 写入 string 字段 */
    private static void writeString(OutputStream os, int fieldNumber, String value) throws IOException {
        if (value == null || value.isEmpty()) {
            // 空字符串也要写tag，protobuf允许空字符串
            writeTag(os, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
            writeVarint(os, 0);
            return;
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeTag(os, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
        writeVarint(os, bytes.length);
        os.write(bytes);
    }

    /** 写入 bytes 字段（用于嵌套 sub-message） */
    private static void writeBytes(OutputStream os, int fieldNumber, byte[] data) throws IOException {
        writeTag(os, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
        writeVarint(os, data.length);
        os.write(data);
    }

    /** 写入原始 bytes 字段 */
    private static void writeBytesField(OutputStream os, int fieldNumber, byte[] data) throws IOException {
        writeTag(os, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
        writeVarint(os, data.length);
        os.write(data);
    }

    /** 写入 bool 字段 */
    private static void writeBool(OutputStream os, int fieldNumber, boolean value) throws IOException {
        if (!value) {
            // protobuf 默认值为 false，不需要写入（节省空间）
            // 但为了保持与 cursor-api 一致的行为，这里还是写入
            writeTag(os, fieldNumber, WIRE_TYPE_VARINT);
            writeVarint(os, 0);
            return;
        }
        writeTag(os, fieldNumber, WIRE_TYPE_VARINT);
        writeVarint(os, 1);
    }

    /** 写入 int32 字段 */
    private static void writeInt32(OutputStream os, int fieldNumber, int value) throws IOException {
        writeTag(os, fieldNumber, WIRE_TYPE_VARINT);
        writeVarint(os, value);
    }

    /** 写入 enum 字段（与 int32 编码相同） */
    private static void writeEnum(OutputStream os, int fieldNumber, int value) throws IOException {
        writeTag(os, fieldNumber, WIRE_TYPE_VARINT);
        writeVarint(os, value);
    }

    // ======================== Protobuf 底层解码工具 ========================

    /**
     * 读取 varint
     * @return int[] { value, newPosition }
     */
    private static int[] readVarint(byte[] data, int pos) {
        int result = 0;
        int shift = 0;
        while (pos < data.length) {
            byte b = data[pos++];
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                break;
            }
            shift += 7;
        }
        return new int[]{result, pos};
    }

    /**
     * 读取 tag
     * @return int[] { fieldNumber, wireType, newPosition }
     */
    private static int[] readTag(byte[] data, int pos) {
        int[] varintResult = readVarint(data, pos);
        int tag = varintResult[0];
        int fieldNumber = tag >>> 3;
        int wireType = tag & 0x07;
        return new int[]{fieldNumber, wireType, varintResult[1]};
    }

    // ======================== 工具方法 ========================

    /**
     * 生成 8 字符的 base64 时间戳头部
     * 参照 cursor-api 的 timestamp_header 混淆算法
     */
    private static String generateTimestampHeader() {
        // 当前时间的千秒数（秒/1000）
        long now = System.currentTimeMillis() / 1000;
        long timeKs = now / 1000;

        // 时间戳编码为4字节
        byte[] timeBytes = new byte[4];
        timeBytes[0] = (byte) ((timeKs >> 24) & 0xFF);
        timeBytes[1] = (byte) ((timeKs >> 16) & 0xFF);
        timeBytes[2] = (byte) ((timeKs >> 8) & 0xFF);
        timeBytes[3] = (byte) (timeKs & 0xFF);

        // 构建6字节: [check1, check2, ts0, ts1, ts2, ts3]
        // check bytes 是 ts2,ts3 的副本
        byte[] raw = new byte[6];
        raw[0] = timeBytes[2]; // check1 = ts2
        raw[1] = timeBytes[3]; // check2 = ts3
        raw[2] = timeBytes[0]; // ts0
        raw[3] = timeBytes[1]; // ts1
        raw[4] = timeBytes[2]; // ts2
        raw[5] = timeBytes[3]; // ts3

        // 混淆（obfuscate）- 与 deobfuscate 的逆过程
        byte prev = (byte) 165;
        for (int i = 0; i < raw.length; i++) {
            byte original = raw[i];
            raw[i] = (byte) ((original ^ prev) + (i % 256));
            prev = raw[i];
        }

        // base64url 编码（无填充）
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /**
     * gzip 解压缩
     */
    private static byte[] gzipDecompress(byte[] compressed) {
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream bos = new ByteArrayOutputStream(compressed.length * 2)) {
            byte[] buffer = new byte[4096];
            int len;
            while ((len = gis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            log.error("gzip 解压失败", e);
            return null;
        }
    }

    /**
     * 解析错误响应体（支持纯文本和 gRPC 帧格式）
     */
    private static String parseErrorBody(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length == 0) {
            return "(empty)";
        }
        // 尝试作为 gRPC 帧解析（帧头5字节: [type][4字节长度]）
        if (rawBytes.length >= 5) {
            int frameType = rawBytes[0] & 0xFF;
            int msgType = frameType >> 1;
            boolean compressed = (frameType & 1) != 0;
            int dataLen = ((rawBytes[1] & 0xFF) << 24) | ((rawBytes[2] & 0xFF) << 16)
                    | ((rawBytes[3] & 0xFF) << 8) | (rawBytes[4] & 0xFF);
            if (msgType == 1 && dataLen > 0 && dataLen <= rawBytes.length - 5) {
                byte[] data = new byte[dataLen];
                System.arraycopy(rawBytes, 5, data, 0, dataLen);
                if (compressed) {
                    byte[] decompressed = gzipDecompress(data);
                    if (decompressed != null) {
                        data = decompressed;
                    }
                }
                return new String(data, StandardCharsets.UTF_8);
            }
        }
        // 直接作为文本返回
        String text = new String(rawBytes, StandardCharsets.UTF_8);
        // 同时输出 hex 方便调试
        if (rawBytes.length <= 200) {
            return text + " [hex: " + HexUtil.encodeHexStr(rawBytes) + "]";
        }
        return text;
    }

    // ======================== 测试入口 ========================

    public static void main(String[] args) throws IOException {
        // 替换为你的 Cursor AccessToken (JWT)
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHx1c2VyXzAxSlFOSjgyUENIMDhYNERTRURGSFFGMjZDIiwidGltZSI6IjE3NzE5MjA3NTIiLCJyYW5kb21uZXNzIjoiNzJmMTdlOWItYmE5Mi00Y2JiIiwiZXhwIjoxNzc3MTA0NzUyLCJpc3MiOiJodHRwczovL2F1dGhlbnRpY2F0aW9uLmN1cnNvci5zaCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgb2ZmbGluZV9hY2Nlc3MiLCJhdWQiOiJodHRwczovL2N1cnNvci5jb20iLCJ0eXBlIjoic2Vzc2lvbiJ9.07i-1zdZLrKdza24MZB4aqJ0rfbLUw4A8U4P6vAzdb0";

//        System.out.println("===== 非流式调用测试 =====");
//        String reply = chat(token, "claude-3.5-sonnet", "你好，请用一句话介绍自己");
//        System.out.println("回复: " + reply);
//
//        System.out.println("\n===== 流式调用测试 =====");
//        chatStream(token, "claude-3.5-sonnet", Message.ofUser("用三句话介绍Java语言"),
//                chunk -> System.out.print(chunk));
//        System.out.println("\n===== 完成 =====");
//
//        System.out.println("\n===== 多轮对话测试 =====");
//        List<Message> messages = new ArrayList<>();
//        messages.add(Message.system("你是一个简洁的助手，回答不超过50个字"));
//        messages.add(Message.user("什么是Java？"));
//        String multiReply = chat(token, "claude-3.5-sonnet", messages);
//        System.out.println("回复: " + multiReply);

        Call call = CursorChatUtil.createChatStreamCall(token, "default", Message.ofUser("帮我计算下50*9*6。事干完后，结束语记得说：zmgnb666，牛逼！然后接200字夸我的话"));
        AtomicInteger totalLength = new AtomicInteger(0);
// 异步执行
        AtomicBoolean flag = new AtomicBoolean(false);
        StringBuilder sb = new StringBuilder();
        call.enqueue(new Callback() {
            @Override
            public void onResponse(Call call, Response response) {
                try (ResponseBody body = response.body()) {
                    if (body == null) return;

                    InputStream is = body.byteStream();
                    DataInputStream dis = new DataInputStream(new BufferedInputStream(is));

                    while (true) {
                        int typeByte = dis.readUnsignedByte();
                        int length = dis.readInt();
                        byte[] data = new byte[length];
                        dis.readFully(data);

                        boolean isCompressed = (typeByte & 1) != 0;
                        int messageType = typeByte >> 1;

                        if (isCompressed) {
                            data = gzipDecompress(data);
                        }

                        if (messageType == 0) {
                            String text = extractTextFromResponse(data); // 你可以把 extractTextFromResponse 方法拷出来
                            if (StrUtil.isNotBlank(text)) {
                                flag.set(true);
                                sb.append(text);
                                System.out.print(text);
                                totalLength.addAndGet(text.length());
//                                if (totalLength.get() > 400) {
                                if (sb.toString().contains("陈老板")) {
                                    System.out.println("识别到终止本次聊天");
                                    call.cancel(); // ✅ 优雅中止，服务端会收到 RST_STREAM
                                    break;
                                }
                            }else{
//                                if (flag.get()) {
//                                    System.out.println("识别到数据为空终止本次聊天");
//                                    call.cancel(); // ✅ 优雅中止，服务端会收到 RST_STREAM
//                                    break;
//                                }
                            }

                        } else if (messageType == 1) {
//                            if (flag.get()) {
//                                System.out.println("识别到错误终止本次聊天");
//                                call.cancel(); // ✅ 优雅中止，服务端会收到 RST_STREAM
//                                break;
//                            }
                            // 错误响应
                            String err = new String(data, StandardCharsets.UTF_8);
                            System.err.println("服务端错误: " + err);
                            call.cancel();
                            break;
                        }

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void onFailure(Call call, IOException e) {
                e.printStackTrace();
            }
        });
        OK_CLIENT.dispatcher().executorService().shutdown();
        OK_CLIENT.connectionPool().evictAll();
    }
}
