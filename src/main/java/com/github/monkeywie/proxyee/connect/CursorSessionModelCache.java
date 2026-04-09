package com.github.monkeywie.proxyee.connect;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.HttpHeaders;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cursor 3.x 常在 Agent {@code RunSSE} 首包只带会话 UUID，模型名出现在同会话稍后到达的 {@code BidiAppend} 等大请求体中。
 * 按 {@code x-session-id} 缓存从 Bidi 解析出的模型 id，供后续 RunSSE→UnifiedChat 改写使用。
 */
public final class CursorSessionModelCache {

    private static final ConcurrentHashMap<String, String> SESSION_TO_MODEL = new ConcurrentHashMap<>();

    private CursorSessionModelCache() {}

    private static String headerInsensitive(HttpHeaders h, String want) {
        if (h == null || want == null) {
            return null;
        }
        String v = h.get(want);
        if (v != null && !v.isEmpty()) {
            return v;
        }
        for (String name : h.names()) {
            if (name != null && name.equalsIgnoreCase(want)) {
                return h.get(name);
            }
        }
        return null;
    }

    /**
     * 在 MITM 转发 Bidi 类请求前调用：从大 body 中启发式提取模型并写入会话缓存。
     */
    public static void maybeIngestFromBidiBody(HttpHeaders headers, String normalizedHttp2Path, ByteBuf body) {
        if (body == null || !body.isReadable()) {
            return;
        }
        if (normalizedHttp2Path == null
                || (!normalizedHttp2Path.contains("Bidi") && !normalizedHttp2Path.contains("bidi"))) {
            return;
        }
        String sid = headerInsensitive(headers, "x-session-id");
        if (sid == null || sid.isEmpty()) {
            return;
        }
        int n = body.readableBytes();
        if (n < 64) {
            return;
        }
        byte[] raw = new byte[n];
        body.getBytes(body.readerIndex(), raw);
        byte[] forParse = raw;
        boolean triedGzip = false;
        int decompressedLen = -1;
        String ce = headerInsensitive(headers, "content-encoding");
        if (ce != null && ce.toLowerCase(Locale.ROOT).contains("gzip")) {
            triedGzip = true;
            byte[] dec = ConnectProtoUtil.gzipDecompress(raw);
            if (dec == null) {
                CursorProxyDebugLog.line(
                        "M_CACHE",
                        "CursorSessionModelCache.maybeIngestFromBidiBody",
                        "bidi_gzip_decode_failed",
                        "{\"compressedLen\":" + n + ",\"pathTail\":\""
                                + CursorProxyDebugLog.esc(tailPath(normalizedHttp2Path)) + "\"}");
                return;
            }
            decompressedLen = dec.length;
            forParse = dec;
        } else if (n >= 2 && (raw[0] & 0xFF) == 0x1f && (raw[1] & 0xFF) == 0x8b) {
            triedGzip = true;
            byte[] dec = ConnectProtoUtil.gzipDecompress(raw);
            if (dec != null) {
                forParse = dec;
                decompressedLen = dec.length;
            }
        }
        if (forParse.length < 64) {
            return;
        }
        String candidate = AgentRunSseModelResolver.extractModelFromProtobufTree(forParse);
        if (candidate == null || !AgentRunSseModelResolver.isPlausibleModelId(candidate)) {
            if (triedGzip) {
                CursorProxyDebugLog.line(
                        "M_CACHE",
                        "CursorSessionModelCache.maybeIngestFromBidiBody",
                        "bidi_gzip_no_model_candidate",
                        "{\"compressedLen\":" + n + ",\"decompressedLen\":" + decompressedLen
                                + ",\"pathTail\":\"" + CursorProxyDebugLog.esc(tailPath(normalizedHttp2Path)) + "\"}");
            }
            return;
        }
        String prev = SESSION_TO_MODEL.put(sid, candidate.trim());
        boolean replaced = prev != null && !prev.equals(candidate.trim());
        CursorProxyDebugLog.line(
                "M_CACHE",
                "CursorSessionModelCache.maybeIngestFromBidiBody",
                "session_model_put",
                "{\"sessionIdPrefix\":\"" + CursorProxyDebugLog.esc(sid.length() > 8 ? sid.substring(0, 8) : sid)
                        + "\",\"model\":\"" + CursorProxyDebugLog.esc(candidate.trim())
                        + "\",\"pathTail\":\"" + CursorProxyDebugLog.esc(tailPath(normalizedHttp2Path))
                        + "\",\"replaced\":" + replaced + "}");
    }

    private static String tailPath(String p) {
        if (p == null) {
            return "";
        }
        int slash = p.lastIndexOf('/');
        return slash >= 0 ? p.substring(slash + 1).toLowerCase(Locale.ROOT) : p;
    }

    public static String getIfPresent(HttpHeaders headers) {
        String sid = headerInsensitive(headers, "x-session-id");
        if (sid == null || sid.isEmpty()) {
            return null;
        }
        return SESSION_TO_MODEL.get(sid);
    }

    public static void put(String sessionId, String model) {
        if (sessionId == null || sessionId.isEmpty() || model == null || model.trim().isEmpty()) {
            return;
        }
        SESSION_TO_MODEL.put(sessionId, model.trim());
    }
}
