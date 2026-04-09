package com.github.monkeywie.proxyee.connect;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.QueryStringDecoder;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 从 RunSSE / Agent 请求中解析 Cursor 实际选用的模型 id，供改写为 UnifiedChat protobuf 时写入 field
 * {@code ModelDetails.model_name}。优先级：query {@code model} &gt; 常见 header &gt; protobuf 内嵌字符串启发式。
 */
public final class AgentRunSseModelResolver {

    /** Agent RunSSE 首帧里 field 1 常为 x-request-id 同类 UUID，绝非 model_name；须整串排除，勿用首字符 [a-zA-Z] 启发式。 */
    private static final Pattern STANDARD_UUID =
            Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    private static final int WIRE_TYPE_VARINT = 0;
    private static final int WIRE_TYPE_64BIT = 1;
    private static final int WIRE_TYPE_LENGTH_DELIMITED = 2;
    private static final int WIRE_TYPE_32BIT = 5;

    private AgentRunSseModelResolver() {}

    public static final class ModelResolution {
        public final String model;
        /** query | header | protobuf | default */
        public final String source;

        ModelResolution(String model, String source) {
            this.model = model;
            this.source = source;
        }
    }

    public static String resolveModel(HttpHeaders headers, String normalizedHttp2Path, byte[] rawAgentBody) {
        return resolveDetail(headers, normalizedHttp2Path, rawAgentBody).model;
    }

    public static ModelResolution resolveDetail(HttpHeaders headers, String normalizedHttp2Path, byte[] rawAgentBody) {
        String fromQuery = parseModelFromQuery(normalizedHttp2Path);
        if (fromQuery != null && !fromQuery.trim().isEmpty()) {
            return new ModelResolution(fromQuery.trim(), "query");
        }
        String fromHeader = parseModelFromHeaders(headers);
        if (fromHeader != null && !fromHeader.isEmpty()) {
            return new ModelResolution(fromHeader.trim(), "header");
        }
        byte[] inner = firstConnectFramePayload(rawAgentBody);
        if (inner != null) {
            String fromProto = extractModelFromProtobufTree(inner);
            if (isPlausibleModelId(fromProto)) {
                return new ModelResolution(fromProto, "protobuf");
            }
        }
        if (rawAgentBody != null && rawAgentBody.length > 0) {
            String fromBlob = extractModelFromProtobufTree(rawAgentBody);
            if (isPlausibleModelId(fromBlob)) {
                return new ModelResolution(fromBlob, "protobuf");
            }
        }
        String fromSession = CursorSessionModelCache.getIfPresent(headers);
        if (fromSession != null && !fromSession.isEmpty()) {
            return new ModelResolution(fromSession.trim(), "session_cache");
        }
        return new ModelResolution("default", "default");
    }

    private static String parseModelFromQuery(String normalizedHttp2Path) {
        if (normalizedHttp2Path == null || !normalizedHttp2Path.contains("=")) {
            return null;
        }
        try {
            QueryStringDecoder dec = new QueryStringDecoder(normalizedHttp2Path, false);
            for (Map.Entry<String, List<String>> e : dec.parameters().entrySet()) {
                String k = e.getKey();
                if (k != null && k.equalsIgnoreCase("model") && !e.getValue().isEmpty()) {
                    return e.getValue().get(0);
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static String parseModelFromHeaders(HttpHeaders headers) {
        if (headers == null) {
            return null;
        }
        String[] names = {
                "x-cursor-model",
                "x-model",
                "x-requested-model",
                "cursor-model",
                "x-cursor-selected-model"
        };
        for (String n : names) {
            String v = headers.get(n);
            if (v != null && !v.isEmpty()) {
                return v.trim();
            }
        }
        for (String name : headers.names()) {
            if (name == null) {
                continue;
            }
            String nl = name.toLowerCase(Locale.ROOT);
            if (nl.contains("model") && !nl.contains("checksum")) {
                String v = headers.get(name);
                if (v != null && !v.isEmpty() && scoreModelString(v.trim()) >= 15) {
                    return v.trim();
                }
            }
        }
        return null;
    }

    /** 与 {@link RunSseToUnifiedChatBodyConverter#extractPromptGuess} 一致的首帧解压载荷。 */
    static byte[] firstConnectFramePayload(byte[] fullBody) {
        if (fullBody == null || fullBody.length < 5) {
            return null;
        }
        int len =
                ((fullBody[1] & 0xFF) << 24)
                        | ((fullBody[2] & 0xFF) << 16)
                        | ((fullBody[3] & 0xFF) << 8)
                        | (fullBody[4] & 0xFF);
        if (len < 0 || len > ConnectProtoUtil.MAX_CONNECT_PAYLOAD_LEN || 5 + len > fullBody.length) {
            return null;
        }
        byte[] payload = Arrays.copyOfRange(fullBody, 5, 5 + len);
        int flags = fullBody[0] & 0xFF;
        boolean compressed = (flags & 1) != 0;
        if (compressed) {
            byte[] d = ConnectProtoUtil.gzipDecompress(payload);
            if (d != null) {
                payload = d;
            }
        }
        return payload;
    }

    /**
     * 递归遍历 protobuf 中所有 length-delimited 字段（含嵌套 message），对 UTF-8 可解码的串打分，取最像模型 id 的一个。
     */
    static String extractModelFromProtobufTree(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        String[] holder = new String[1];
        int[] scoreHolder = new int[1];
        collectModelCandidates(data, 0, 6, holder, scoreHolder);
        return holder[0];
    }

    private static void collectModelCandidates(
            byte[] data, int depth, int maxDepth, String[] bestOut, int[] bestScoreOut) {
        if (data == null || data.length == 0 || depth > maxDepth) {
            return;
        }
        int pos = 0;
        while (pos < data.length) {
            int[] tag = readTag(data, pos);
            if (tag == null) {
                break;
            }
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == WIRE_TYPE_LENGTH_DELIMITED) {
                int[] lenR = readVarint(data, pos);
                if (lenR == null) {
                    break;
                }
                int blen = lenR[0];
                pos = lenR[1];
                if (blen < 0 || pos + blen > data.length) {
                    break;
                }
                byte[] chunk = Arrays.copyOfRange(data, pos, pos + blen);
                pos += blen;
                String s = tryUtf8(chunk);
                if (s != null) {
                    int sc = scoreModelString(s);
                    if (sc > bestScoreOut[0]) {
                        bestScoreOut[0] = sc;
                        bestOut[0] = s.trim();
                    }
                }
                collectModelCandidates(chunk, depth + 1, maxDepth, bestOut, bestScoreOut);
            } else if (wireType == WIRE_TYPE_VARINT) {
                int[] vr = readVarint(data, pos);
                if (vr == null) {
                    break;
                }
                pos = vr[1];
            } else if (wireType == WIRE_TYPE_64BIT) {
                pos += 8;
            } else if (wireType == WIRE_TYPE_32BIT) {
                pos += 4;
            } else {
                break;
            }
        }
    }

    private static String tryUtf8(byte[] chunk) {
        if (chunk.length > 512) {
            return null;
        }
        String s = new String(chunk, StandardCharsets.UTF_8);
        int bad = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\uFFFD') {
                bad++;
            }
        }
        if (bad > 0) {
            return null;
        }
        return s;
    }

    static int scoreModelString(String t) {
        if (t == null) {
            return 0;
        }
        t = t.trim();
        if (t.length() < 4 || t.length() > 120) {
            return 0;
        }
        if (STANDARD_UUID.matcher(t).matches()) {
            return 0;
        }
        if (t.indexOf('\n') >= 0 || t.indexOf('\r') >= 0) {
            return 0;
        }
        String low = t.toLowerCase(Locale.ROOT);
        int score = 0;
        if (low.contains("claude")) {
            score += 55;
        }
        if (low.contains("gpt")) {
            score += 55;
        }
        if (low.contains("gemini")) {
            score += 55;
        }
        if (low.contains("grok")) {
            score += 55;
        }
        if (low.contains("deepseek")) {
            score += 55;
        }
        if (low.contains("sonnet") || low.contains("opus") || low.contains("haiku")) {
            score += 35;
        }
        if (t.chars().filter(ch -> ch == '-').count() >= 2) {
            score += 15;
        }
        if (t.matches("^[a-zA-Z][a-zA-Z0-9_.-]+$")) {
            score += 25;
        }
        if (low.equals("default")) {
            score = Math.min(score, 5);
        }
        if (t.contains("http://") || t.contains("https://") || t.contains("{")) {
            score -= 80;
        }
        if (t.contains(" ") && score < 40) {
            score -= 30;
        }
        return Math.max(0, score);
    }

    /** 供 {@link CursorSessionModelCache} 等包内调用。 */
    public static boolean isPlausibleModelId(String s) {
        return s != null && !s.isEmpty() && scoreModelString(s) >= 25;
    }

    private static int[] readTag(byte[] data, int pos) {
        int[] vr = readVarint(data, pos);
        if (vr == null) {
            return null;
        }
        int tag = vr[0];
        int newPos = vr[1];
        int fieldNumber = tag >>> 3;
        int wireType = tag & 0x07;
        if (fieldNumber == 0) {
            return null;
        }
        return new int[]{fieldNumber, wireType, newPos};
    }

    private static int[] readVarint(byte[] data, int pos) {
        int result = 0;
        int shift = 0;
        int p = pos;
        while (p < data.length) {
            byte b = data[p++];
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return new int[]{result, p};
            }
            shift += 7;
            if (shift > 63) {
                return null;
            }
        }
        return null;
    }
}
