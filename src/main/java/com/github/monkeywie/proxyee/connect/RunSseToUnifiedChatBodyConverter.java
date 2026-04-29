package com.github.monkeywie.proxyee.connect;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.HttpHeaders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 当客户端路径为 RunSSE/Agent 等，而上游已由代理固定为 {@code StreamUnifiedChatWithTools} 时，
 * 将请求体替换为 {@link CursorConnectUpstreamCodec} 与 {@link com.github.monkeywie.proxyee.CursorChatUtil} 一致的 Connect 帧。
 */
public final class RunSseToUnifiedChatBodyConverter {

    private static final Logger LOG = Logger.getLogger(RunSseToUnifiedChatBodyConverter.class.getName());

    // #region agent log
    private static String dbgEsc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void dbg(String hypothesisId, String message, String dataJson) {
        try {
            String line = "{\"timestamp\":" + System.currentTimeMillis() + ",\"hypothesisId\":\"" + hypothesisId
                    + "\",\"location\":\"RunSseToUnifiedChatBodyConverter\",\"message\":\"" + message
                    + "\",\"data\":" + dataJson + "}\n";
            Files.write(Paths.get(CursorProxyDebugLog.PATH), line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }
    // #endregion

    private RunSseToUnifiedChatBodyConverter() {}

    /**
     * @param normalizedHttp2Path {@link com.github.monkeywie.proxyee.intercept.cursor.CursorHttp2StreamAbortIntercept}
     *                            中 {@code normalizeToHttp2Path} 的结果
     * @param headers             原始请求头（用于解析模型名等）
     */
    public static ByteBuf maybeRewriteBodyForUnifiedChat(ByteBuf body, String normalizedHttp2Path, HttpHeaders headers) {
        if (body == null) {
            return Unpooled.EMPTY_BUFFER;
        }
        if (normalizedHttp2Path == null) {
            return body;
        }
        if (normalizedHttp2Path.contains("StreamUnifiedChatWithTools")) {
            // #region agent log
            dbg("H1", "skip_rewrite", "{\"reason\":\"client_already_unified_chat\"}");
            // #endregion
            return body;
        }
        // 注：早期对 Agent/RunSSE 透传上游，现已统一固定为 StreamUnifiedChatWithTools，故所有 RunSSE/Agent 请求体均需转换
        boolean looksRunSse =
                normalizedHttp2Path.contains("RunSSE")
                        || normalizedHttp2Path.contains("agent.v1.AgentService");
        if (!looksRunSse) {
            // #region agent log
            dbg("H1", "skip_rewrite", "{\"reason\":\"not_run_sse_path\"}");
            // #endregion
            return body;
        }
        try {
            byte[] raw = new byte[body.readableBytes()];
            body.getBytes(body.readerIndex(), raw);
            if (raw.length == 0) {
                CursorProxyDebugLog.line("M_EMPTY", "RunSseToUnifiedChatBodyConverter", "run_sse_zero_byte_body",
                        "{\"note\":\"client_post_empty_body_still_build_minimal_unified_chat\"}");
            }
            // #region agent log — 仅记录证据，不在此轮改解析策略
            CursorProxyDebugLog.logModelIngestPipeline(headers, normalizedHttp2Path, raw);
            // #endregion
            String hint = extractPromptGuess(raw);
            AgentRunSseModelResolver.ModelResolution mr =
                    AgentRunSseModelResolver.resolveDetail(headers, normalizedHttp2Path, raw);
            boolean modelLooksAuto = mr.model != null && "auto".equalsIgnoreCase(mr.model.trim());
            CursorProxyDebugLog.logModelResolutionOutcome(mr, modelLooksAuto);
            byte[] replaced = CursorConnectUpstreamCodec.buildFramedUnifiedChatBody(mr.model, hint);
            // #region agent log
            dbg("H2", "rewritten_to_unified_chat", "{\"inBytes\":" + raw.length + ",\"outBytes\":"
                    + replaced.length + ",\"hintLen\":" + hint.length() + ",\"model\":\"" + dbgEsc(mr.model)
                    + "\",\"modelSource\":\"" + dbgEsc(mr.source) + "\",\"modelLooksAuto\":" + modelLooksAuto + "}");
            // #endregion
            body.release();
            return Unpooled.wrappedBuffer(replaced);
        } catch (Exception e) {
            // #region agent log
            dbg("H3", "rewrite_exception", "{\"err\":\"" + e.getClass().getName() + "\"}");
            // #endregion
            LOG.log(Level.WARNING, "[RunSseToUnifiedChat] rewrite failed, forwarding original body", e);
            return body;
        }
    }

    /**
     * 在上游连接就绪、即将写出前再次解析模型：此时同会话的 {@code BidiAppend} 可能已解压写入 {@link CursorSessionModelCache}，
     * 若命中 {@code session_cache} 则用新模型重建 UnifiedChat 帧并释放旧 buffer。
     */
    public static ByteBuf maybeUpgradeBodyWithLateSessionCache(
            ByteBuf bodyAfterRewrite, HttpHeaders headers, String normalizedHttp2Path, byte[] rawOriginalRunSse) {
        if (bodyAfterRewrite == null || rawOriginalRunSse == null || rawOriginalRunSse.length == 0) {
            return bodyAfterRewrite;
        }
        if (normalizedHttp2Path == null
                || (!normalizedHttp2Path.contains("RunSSE")
                        && !normalizedHttp2Path.contains("agent.v1.AgentService"))) {
            return bodyAfterRewrite;
        }
        if (normalizedHttp2Path.contains("StreamUnifiedChatWithTools")) {
            return bodyAfterRewrite;
        }
        try {
            AgentRunSseModelResolver.ModelResolution mr =
                    AgentRunSseModelResolver.resolveDetail(headers, normalizedHttp2Path, rawOriginalRunSse);
            if (!"session_cache".equals(mr.source)) {
                return bodyAfterRewrite;
            }
            String hint = extractPromptGuess(rawOriginalRunSse);
            byte[] replaced = CursorConnectUpstreamCodec.buildFramedUnifiedChatBody(mr.model, hint);
            bodyAfterRewrite.release();
            CursorProxyDebugLog.line(
                    "M_LATE",
                    "RunSseToUnifiedChatBodyConverter.maybeUpgradeBodyWithLateSessionCache",
                    "late_session_cache_apply",
                    "{\"model\":\"" + CursorProxyDebugLog.esc(mr.model) + "\"}");
            return Unpooled.wrappedBuffer(replaced);
        } catch (Exception e) {
            return bodyAfterRewrite;
        }
    }

    /**
     * 从首帧 Connect payload（可能 gzip）中启发式提取用户可见文本，失败则返回空串。
     */
   public static String extractPromptGuess(byte[] fullBody) {
        if (fullBody == null || fullBody.length < 5) {
            return "";
        }
        int len =
                ((fullBody[1] & 0xFF) << 24)
                        | ((fullBody[2] & 0xFF) << 16)
                        | ((fullBody[3] & 0xFF) << 8)
                        | (fullBody[4] & 0xFF);
        if (len < 0 || len > ConnectProtoUtil.MAX_CONNECT_PAYLOAD_LEN || 5 + len > fullBody.length) {
            return longestUtf8LikelyPrompt(Arrays.copyOfRange(fullBody, 0, Math.min(fullBody.length, 64 * 1024)));
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
        return longestUtf8LikelyPrompt(payload);
    }

    private static String longestUtf8LikelyPrompt(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return "";
        }
        String s = new String(payload, StandardCharsets.UTF_8);
        StringBuilder cur = new StringBuilder();
        String best = "";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t') {
                if (cur.length() > best.length()) {
                    best = cur.toString();
                }
                cur.setLength(0);
            } else if (c != '\uFFFD' || cur.length() > 0) {
                cur.append(c);
            }
        }
        if (cur.length() > best.length()) {
            best = cur.toString();
        }
        best = best.trim().replaceAll("\r\n|\n|\r", " ");
        if (best.length() > 8000) {
            best = best.substring(0, 8000);
        }
        return best;
    }
}
