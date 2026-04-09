package com.github.monkeywie.proxyee.connect;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.handler.codec.http2.Http2Headers;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 代理调试 NDJSON（单文件追加），供分析 RunSSE↔UnifiedChat、模型解析、下行格式等；不含 token 等敏感值原文。
 */
public final class CursorProxyDebugLog {

    /** 与工程根目录下 {@code .cursor/debug.log} 对齐，避免写错仓库目录名。 */
    public static final String PATH = Paths.get(System.getProperty("user.dir", "."), ".cursor", "debug.log")
            .toAbsolutePath()
            .toString();

    private CursorProxyDebugLog() {}

    public static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    /** 十六进制前缀，用于对照 protobuf / Connect 帧形态（不含明文密钥）。 */
    public static String hexPrefix(byte[] b, int maxBytes) {
        if (b == null || b.length == 0) {
            return "";
        }
        int n = Math.min(maxBytes, b.length);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        if (b.length > maxBytes) {
            sb.append("…");
        }
        return sb.toString();
    }

    public static void line(String hypothesisId, String location, String message, String dataJsonObject) {
        try {
            String line = "{\"timestamp\":" + System.currentTimeMillis()
                    + ",\"hypothesisId\":\"" + esc(hypothesisId)
                    + "\",\"location\":\"" + esc(location)
                    + "\",\"message\":\"" + esc(message)
                    + "\",\"data\":" + dataJsonObject + "}\n";
            Files.write(Paths.get(PATH), line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }

    private static boolean isSensitiveHeader(String name) {
        if (name == null) {
            return true;
        }
        String n = name.toLowerCase(Locale.ROOT);
        return n.contains("authorization")
                || n.equals("cookie")
                || n.equals("proxy-authorization")
                || n.contains("x-cursor-checksum")
                || n.contains("x-amz-")
                || n.contains("x-api-key");
    }

    private static void appendHttpHeadersArrayJson(StringBuilder data, HttpHeaders headers) {
        data.append('[');
        boolean firstH = true;
        if (headers != null) {
            for (String name : headers.names()) {
                String val = headers.get(name);
                if (!firstH) {
                    data.append(',');
                }
                firstH = false;
                data.append('{');
                data.append("\"name\":\"").append(esc(name)).append('\"');
                if (isSensitiveHeader(name)) {
                    data.append(",\"value\":\"[redacted]\"");
                } else {
                    String v = val == null ? "" : val;
                    if (v.length() > 400) {
                        v = v.substring(0, 400) + "…";
                    }
                    data.append(",\"value\":\"").append(esc(v)).append('\"');
                }
                data.append('}');
            }
        }
        data.append(']');
    }

    private static String getHeaderInsensitive(HttpHeaders headers, String want) {
        if (headers == null || want == null) {
            return null;
        }
        String v = headers.get(want);
        if (v != null && !v.isEmpty()) {
            return v;
        }
        for (String name : headers.names()) {
            if (name != null && name.equalsIgnoreCase(want)) {
                return headers.get(name);
            }
        }
        return null;
    }

    private static String getFromHttp2Insensitive(Http2Headers h2, String wantLower) {
        if (h2 == null || wantLower == null) {
            return null;
        }
        CharSequence cs = h2.get(wantLower);
        if (cs != null && cs.length() > 0) {
            return cs.toString();
        }
        for (Map.Entry<CharSequence, CharSequence> e : h2) {
            if (e.getKey() != null && e.getKey().toString().equalsIgnoreCase(wantLower)) {
                return e.getValue() != null ? e.getValue().toString() : "";
            }
        }
        return null;
    }

    /**
     * 下游 MITM 收到的、即将发往上游的 HTTP/1 头副本（{@code buildHttp2Headers} 之前），用于对照是否缺 {@code x-cursor-client-version} 等。
     */
    public static void logClientForwardHeadersSnapshot(
            HttpHeaders forwardHeaders, String clientNormalizedPath, String upstreamPath, boolean scanAbort) {
        String xVer = getHeaderInsensitive(forwardHeaders, "x-cursor-client-version");
        StringBuilder data = new StringBuilder(4096);
        data.append('{');
        data.append("\"phase\":\"client_forward_http1_copy\"");
        data.append(",\"clientNormalizedPath\":\"").append(esc(clientNormalizedPath)).append('\"');
        data.append(",\"upstreamPath\":\"").append(esc(upstreamPath)).append('\"');
        data.append(",\"scanAbort\":").append(scanAbort);
        data.append(",\"xCursorClientVersion\":\"").append(esc(xVer == null ? "" : xVer)).append('\"');
        data.append(",\"headers\":");
        appendHttpHeadersArrayJson(data, forwardHeaders);
        data.append('}');
        line("H_HDR_FWD", "CursorProxyDebugLog.logClientForwardHeadersSnapshot", "client_forward_headers_before_h2", data.toString());
    }

    /**
     * 实际写入上游 HTTP/2 流的伪头 + 头（与 {@code buildHttp2Headers} 输出一致），用于确认上游收到的 {@code :authority}、{@code :path} 及 Cursor 相关头。
     */
    public static void logUpstreamHttp2HeadersSnapshot(
            Http2Headers h2h, String clientNormalizedPath, String upstreamPath, boolean scanAbort) {
        String xVer = getFromHttp2Insensitive(h2h, "x-cursor-client-version");
        StringBuilder data = new StringBuilder(4096);
        data.append('{');
        data.append("\"phase\":\"upstream_http2_wire\"");
        data.append(",\"clientNormalizedPath\":\"").append(esc(clientNormalizedPath)).append('\"');
        data.append(",\"upstreamPath\":\"").append(esc(upstreamPath)).append('\"');
        data.append(",\"scanAbort\":").append(scanAbort);
        data.append(",\"xCursorClientVersion\":\"").append(esc(xVer == null ? "" : xVer)).append('\"');
        data.append(",\"pseudoAndHeaders\":[");
        boolean first = true;
        if (h2h != null) {
            for (Map.Entry<CharSequence, CharSequence> e : h2h) {
                if (!first) {
                    data.append(',');
                }
                first = false;
                String name = e.getKey() != null ? e.getKey().toString() : "";
                String val = e.getValue() != null ? e.getValue().toString() : "";
                data.append('{');
                data.append("\"name\":\"").append(esc(name)).append('\"');
                if (isSensitiveHeader(name)) {
                    data.append(",\"value\":\"[redacted]\"");
                } else {
                    String v = val.length() > 400 ? val.substring(0, 400) + "…" : val;
                    data.append(",\"value\":\"").append(esc(v)).append('\"');
                }
                data.append('}');
            }
        }
        data.append("]}");
        line("H_HDR_H2", "CursorProxyDebugLog.logUpstreamHttp2HeadersSnapshot", "upstream_http2_headers_after_build", data.toString());
    }

    /** 记录模型解析前的可观测输入：query、头（脱敏）、body 长度与 hex 前缀。 */
    public static void logModelIngestPipeline(
            HttpHeaders headers, String normalizedHttp2Path, byte[] rawBody) {
        StringBuilder data = new StringBuilder(2048);
        data.append('{');
        data.append("\"normalizedPath\":\"").append(esc(normalizedHttp2Path)).append('\"');
        data.append(",\"rawBodyLen\":").append(rawBody == null ? 0 : rawBody.length);
        data.append(",\"rawBodyHexPrefix\":\"").append(hexPrefix(rawBody, 96)).append('\"');

        data.append(",\"queryParams\":{");
        boolean firstQ = true;
        if (normalizedHttp2Path != null && normalizedHttp2Path.contains("?")) {
            try {
                QueryStringDecoder dec = new QueryStringDecoder(normalizedHttp2Path, false);
                for (Map.Entry<String, List<String>> e : dec.parameters().entrySet()) {
                    String k = e.getKey();
                    if (k == null) {
                        continue;
                    }
                    if (!firstQ) {
                        data.append(',');
                    }
                    firstQ = false;
                    data.append('\"').append(esc(k)).append("\":");
                    List<String> vals = e.getValue();
                    if (vals == null || vals.isEmpty()) {
                        data.append("[]");
                    } else if (vals.size() == 1) {
                        data.append('\"').append(esc(vals.get(0))).append('\"');
                    } else {
                        data.append('[');
                        for (int i = 0; i < vals.size(); i++) {
                            if (i > 0) {
                                data.append(',');
                            }
                            data.append('\"').append(esc(vals.get(i))).append('\"');
                        }
                        data.append(']');
                    }
                }
            } catch (Exception ignored) {
            }
        }
        data.append('}');

        data.append(",\"headers\":");
        appendHttpHeadersArrayJson(data, headers);

        byte[] inner = AgentRunSseModelResolver.firstConnectFramePayload(rawBody);
        data.append(",\"firstConnectInnerLen\":").append(inner == null ? -1 : inner.length);
        data.append(",\"firstConnectInnerHexPrefix\":\"").append(hexPrefix(inner, 64)).append('\"');
        data.append('}');

        line("M_INGEST", "CursorProxyDebugLog.logModelIngestPipeline", "run_sse_model_inputs", data.toString());
    }

    public static void logModelResolutionOutcome(
            AgentRunSseModelResolver.ModelResolution mr, boolean modelLooksAuto) {
        String data = "{\"resolvedModel\":\"" + esc(mr.model)
                + "\",\"source\":\"" + esc(mr.source)
                + "\",\"modelLooksAuto\":" + modelLooksAuto + "}";
        line("M_RESOLVE", "CursorProxyDebugLog.logModelResolutionOutcome", "resolved", data);
    }
}
