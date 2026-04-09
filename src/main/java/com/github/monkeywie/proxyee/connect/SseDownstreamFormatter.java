package com.github.monkeywie.proxyee.connect;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 将上游 gRPC Connect 流式结果格式化为标准 SSE（{@code text/event-stream}）下行给 HTTP/1.1 客户端。
 * <p>OpenAI 兼容 {@code data:} 行参考公开 gist（Cursor→本地 LLM 代理）与常见流式补全形状：
 * {@code {"choices":[{"delta":{"content":"..."}}]}}。
 */
public final class SseDownstreamFormatter {

    private SseDownstreamFormatter() {}

    public static String jsonQuote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /** 单行 payload（通常为 JSON）→ {@code data: ...\n\n} */
    public static ByteBuf sseDataLineUtf8(String payloadSingleLine) {
        StringBuilder sb = new StringBuilder(payloadSingleLine.length() + 16);
        sb.append("data: ");
        String[] lines = payloadSingleLine.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                sb.append("\ndata: ");
            }
            sb.append(lines[i]);
        }
        sb.append("\n\n");
        return Unpooled.copiedBuffer(sb.toString(), StandardCharsets.UTF_8);
    }

    /** OpenAI 风格流结束标记 */
    public static ByteBuf sseDoneLine() {
        return Unpooled.copiedBuffer("data: [DONE]\n\n", StandardCharsets.UTF_8);
    }

    public static String connectMsg0Json(String text) {
        String t = text == null ? "" : text;
        return "{\"messageType\":0,\"text\":" + jsonQuote(t) + "}";
    }

    /**
     * OpenAI chat completions 流式单块 JSON（单行，无换行），与公开 Cursor 代理 gist 中 {@code choices[0].delta.content} 一致。
     */
    public static String openAiChatCompletionDeltaJson(String deltaContent) {
        String d = deltaContent == null ? "" : deltaContent;
        return "{\"choices\":[{\"delta\":{\"content\":" + jsonQuote(d) + "}}]}";
    }

    /** msgType=1 时 payload 已为 UTF-8 JSON，直接作为 SSE 一行 data */
    public static ByteBuf connectMsg1JsonPayload(byte[] payloadUtf8) {
        String body = new String(payloadUtf8, StandardCharsets.UTF_8);
        return sseDataLineUtf8(body);
    }

    /** 无法解析时的兜底（截断避免日志/缓冲过大） */
    public static String connectFallbackJson(int messageType, byte[] wire) {
        String b64 = Base64.getEncoder().encodeToString(wire);
        int max = 16384;
        if (b64.length() > max) {
            b64 = b64.substring(0, max) + "…";
        }
        return "{\"messageType\":" + messageType + ",\"wireB64\":\"" + b64 + "\"}";
    }
}
