package com.github.monkeywie.proxyee.connect;

import cn.hutool.core.util.HexUtil;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaders;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
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
    private static final int UNIFIED_MODE_AGENT = 2;
    private static final int UNIFIED_MODE_PLAN = 5;
    private static final int UNIFIED_MODE_DEBUG = 6;

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

    public static final class UnifiedChatTool {
        public final String name;
        public final String description;
        public final String parameters;
        public final String serverName;

        public UnifiedChatTool(String name, String description, String parameters, String serverName) {
            this.name = name;
            this.description = description;
            this.parameters = parameters;
            this.serverName = serverName;
        }
    }

    public static final class WorkspaceFolderContext {
        public final String uri;
        public final String name;

        public WorkspaceFolderContext(String uri, String name) {
            this.uri = uri;
            this.name = name;
        }
    }

    public static final class EnvironmentContext {
        public final String exthostPlatform;
        public final String exthostRelease;
        public final String exthostShell;
        public final String localOsType;
        public final String localTimezone;
        public final String homeDirectory;
        public final List<String> workspaceUris;
        public final String cursorVersion;

        public EnvironmentContext(String exthostPlatform,
                                  String exthostRelease,
                                  String exthostShell,
                                  String localOsType,
                                  String localTimezone,
                                  String homeDirectory,
                                  List<String> workspaceUris,
                                  String cursorVersion) {
            this.exthostPlatform = exthostPlatform;
            this.exthostRelease = exthostRelease;
            this.exthostShell = exthostShell;
            this.localOsType = localOsType;
            this.localTimezone = localTimezone;
            this.homeDirectory = homeDirectory;
            this.workspaceUris = workspaceUris == null
                    ? Collections.<String>emptyList()
                    : new ArrayList<String>(workspaceUris);
            this.cursorVersion = cursorVersion;
        }
    }

    public static final class UnifiedChatBridgeContext {
        public final String extraSystemPrompt;
        public final int unifiedMode;
        public final String unifiedModeName;
        public final boolean disableTools;
        public final boolean usesRules;
        public final boolean supportsMermaidDiagrams;
        public final boolean hasMcpDescriptors;
        public final String terminalsFolder;
        public final String agentTranscriptsFolder;
        public final String customPlanningInstructions;
        public final List<Integer> supportedTools;
        public final List<UnifiedChatTool> mcpTools;
        public final List<WorkspaceFolderContext> workspaceFolders;
        public final EnvironmentContext environment;

        public UnifiedChatBridgeContext(String extraSystemPrompt,
                                        int unifiedMode,
                                        String unifiedModeName,
                                        boolean disableTools,
                                        boolean usesRules,
                                        boolean supportsMermaidDiagrams,
                                        boolean hasMcpDescriptors,
                                        String terminalsFolder,
                                        String agentTranscriptsFolder,
                                        String customPlanningInstructions,
                                        List<Integer> supportedTools,
                                        List<UnifiedChatTool> mcpTools,
                                        List<WorkspaceFolderContext> workspaceFolders,
                                        EnvironmentContext environment) {
            this.extraSystemPrompt = extraSystemPrompt;
            this.unifiedMode = unifiedMode;
            this.unifiedModeName = unifiedModeName;
            this.disableTools = disableTools;
            this.usesRules = usesRules;
            this.supportsMermaidDiagrams = supportsMermaidDiagrams;
            this.hasMcpDescriptors = hasMcpDescriptors;
            this.terminalsFolder = terminalsFolder;
            this.agentTranscriptsFolder = agentTranscriptsFolder;
            this.customPlanningInstructions = customPlanningInstructions;
            this.supportedTools = supportedTools == null
                    ? Collections.<Integer>emptyList()
                    : new ArrayList<Integer>(supportedTools);
            this.mcpTools = mcpTools == null
                    ? Collections.<UnifiedChatTool>emptyList()
                    : new ArrayList<UnifiedChatTool>(mcpTools);
            this.workspaceFolders = workspaceFolders == null
                    ? Collections.<WorkspaceFolderContext>emptyList()
                    : new ArrayList<WorkspaceFolderContext>(workspaceFolders);
            this.environment = environment;
        }

        public static UnifiedChatBridgeContext ask(String extraSystemPrompt) {
            return new UnifiedChatBridgeContext(
                    extraSystemPrompt,
                    UNIFIED_MODE_CHAT,
                    "Agent",
                    true,
                    extraSystemPrompt != null && !extraSystemPrompt.trim().isEmpty(),
                    false,
                    false,
                    null,
                    null,
                    null,
                    Collections.<Integer>emptyList(),
                    Collections.<UnifiedChatTool>emptyList(),
                    Collections.<WorkspaceFolderContext>emptyList(),
                    null);
        }

        public static int modeFromName(String modeName) {
            if (modeName == null) {
                return UNIFIED_MODE_CHAT;
            }
            String normalized = modeName.trim().toLowerCase();
            if ("agent".equals(normalized) || "project".equals(normalized) || "triage".equals(normalized)) {
                return UNIFIED_MODE_AGENT;
            }
            if ("plan".equals(normalized)) {
                return UNIFIED_MODE_PLAN;
            }
            if ("debug".equals(normalized)) {
                return UNIFIED_MODE_DEBUG;
            }
            return UNIFIED_MODE_CHAT;
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
        byte[] protobufBody = buildChatRequestProtobuf(
                model,
                Message.ofUser(userText != null ? userText : ""),
                UnifiedChatBridgeContext.ask(null));
        return wrapGrpcFrame(protobufBody, false);
    }

    public static byte[] buildFramedUnifiedChatBody(String model, String userText, String extraSystemPrompt)
            throws IOException {
        byte[] protobufBody = buildChatRequestProtobuf(
                model,
                Message.ofUser(userText != null ? userText : ""),
                UnifiedChatBridgeContext.ask(extraSystemPrompt));
        return wrapGrpcFrame(protobufBody, false);
    }

    public static byte[] buildFramedUnifiedChatBody(String model,
                                                    String userText,
                                                    UnifiedChatBridgeContext bridgeContext)
            throws IOException {
        byte[] protobufBody = buildChatRequestProtobuf(
                model,
                Message.ofUser(userText != null ? userText : ""),
                bridgeContext);
        return wrapGrpcFrame(protobufBody, false);
    }

    /**
     * 构建 StreamUnifiedChatRequestWithTools 外层 protobuf（与 CursorChatUtil 一致）。
     */
    public static byte[] buildChatRequestProtobuf(String model, List<? extends Message> messages) throws IOException {
        return buildChatRequestProtobuf(model, messages, UnifiedChatBridgeContext.ask(null));
    }

    public static byte[] buildChatRequestProtobuf(String model,
                                                  List<? extends Message> messages,
                                                  UnifiedChatBridgeContext bridgeContext) throws IOException {
        UnifiedChatBridgeContext effectiveContext =
                bridgeContext == null ? UnifiedChatBridgeContext.ask(null) : bridgeContext;
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

        if (effectiveContext.extraSystemPrompt != null && !effectiveContext.extraSystemPrompt.trim().isEmpty()) {
            if (systemPrompt.length() > 0) {
                systemPrompt.append("\n\n");
            }
            systemPrompt.append(effectiveContext.extraSystemPrompt.trim());
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

        byte[] envInfo = buildEnvironmentInfo(effectiveContext.environment);
        writeBytes(requestBuf, 26, envInfo);

        writeBool(requestBuf, 37, false);
        for (Integer supportedTool : effectiveContext.supportedTools) {
            if (supportedTool != null) {
                writeEnum(requestBuf, 29, supportedTool.intValue());
            }
        }
        for (UnifiedChatTool tool : effectiveContext.mcpTools) {
            byte[] mcpTool = buildMcpTool(tool);
            if (mcpTool.length > 0) {
                writeBytes(requestBuf, 34, mcpTool);
            }
        }
        writeEnum(requestBuf, 46, effectiveContext.unifiedMode);
        writeBool(requestBuf, 48, effectiveContext.disableTools);
        writeBool(requestBuf, 51, effectiveContext.usesRules);
        writeString(requestBuf, 54, firstNonBlank(effectiveContext.unifiedModeName, "Ask"));
        writeBool(requestBuf, 65, effectiveContext.supportsMermaidDiagrams);
        for (WorkspaceFolderContext folder : effectiveContext.workspaceFolders) {
            byte[] workspaceFolder = buildWorkspaceFolder(folder);
            if (workspaceFolder.length > 0) {
                writeBytes(requestBuf, 81, workspaceFolder);
            }
        }
        if (effectiveContext.customPlanningInstructions != null
                && !effectiveContext.customPlanningInstructions.trim().isEmpty()) {
            writeString(requestBuf, 84, effectiveContext.customPlanningInstructions.trim());
        }
        if (effectiveContext.terminalsFolder != null && !effectiveContext.terminalsFolder.trim().isEmpty()) {
            writeString(requestBuf, 86, effectiveContext.terminalsFolder.trim());
        }
        if (effectiveContext.hasMcpDescriptors) {
            writeBool(requestBuf, 90, true);
        }
        if (effectiveContext.agentTranscriptsFolder != null
                && !effectiveContext.agentTranscriptsFolder.trim().isEmpty()) {
            writeString(requestBuf, 93, effectiveContext.agentTranscriptsFolder.trim());
        }

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

    private static byte[] buildEnvironmentInfo(EnvironmentContext environment) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        EnvironmentContext effectiveEnvironment = environment == null
                ? new EnvironmentContext(
                        "win32",
                        null,
                        null,
                        "Windows",
                        null,
                        null,
                        Collections.<String>emptyList(),
                        CLIENT_VERSION)
                : environment;
        writeString(buf, 1, firstNonBlank(effectiveEnvironment.exthostPlatform, "win32"));
        writeString(buf, 3, firstNonBlank(effectiveEnvironment.exthostRelease, ""));
        writeString(buf, 4, firstNonBlank(effectiveEnvironment.exthostShell, ""));
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        writeString(buf, 5, timestamp);
        for (String workspaceUri : effectiveEnvironment.workspaceUris) {
            if (workspaceUri != null && !workspaceUri.trim().isEmpty()) {
                writeString(buf, 6, workspaceUri.trim());
            }
        }
        writeString(buf, 7, firstNonBlank(effectiveEnvironment.cursorVersion, CLIENT_VERSION));
        writeString(buf, 9, firstNonBlank(effectiveEnvironment.localOsType, ""));
        writeString(buf, 10, firstNonBlank(effectiveEnvironment.homeDirectory, ""));
        writeString(buf, 11, firstNonBlank(effectiveEnvironment.localTimezone, ""));
        return buf.toByteArray();
    }

    private static byte[] buildMcpTool(UnifiedChatTool tool) throws IOException {
        if (tool == null) {
            return new byte[0];
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
        if (tool.name != null && !tool.name.trim().isEmpty()) {
            writeString(buf, 1, tool.name.trim());
        }
        if (tool.description != null && !tool.description.trim().isEmpty()) {
            writeString(buf, 2, tool.description.trim());
        }
        writeString(buf, 3, firstNonBlank(tool.parameters, "{}"));
        if (tool.serverName != null && !tool.serverName.trim().isEmpty()) {
            writeString(buf, 4, tool.serverName.trim());
        }
        return buf.toByteArray();
    }

    private static byte[] buildWorkspaceFolder(WorkspaceFolderContext folder) throws IOException {
        if (folder == null) {
            return new byte[0];
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream(96);
        if (folder.uri != null && !folder.uri.trim().isEmpty()) {
            writeString(buf, 1, folder.uri.trim());
        }
        if (folder.name != null && !folder.name.trim().isEmpty()) {
            writeString(buf, 2, folder.name.trim());
        }
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

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null) {
                String trimmed = value.trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            }
        }
        return null;
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
