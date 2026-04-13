package com.github.monkeywie.proxyee.connect;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 解析 OpenAI Chat Completions SSE 的 data 行，抽取 choices[0].delta.content。
 */
public final class OpenAiSseDeltaParser {

    private OpenAiSseDeltaParser() {
    }

    /**
     * @param sseChunkFromUpstream 一段 SSE（可能包含多行 data: ... 与空行分隔）
     * @return 拼接后的 delta 文本（可能为空串）；若未包含可用 delta 返回 null
     */
    public static String extractDeltaText(String sseChunkFromUpstream) {
        if (StrUtil.isBlank(sseChunkFromUpstream)) {
            return null;
        }
        String[] lines = sseChunkFromUpstream.split("\n");
        StringBuilder out = null;
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            String t = line.trim();
            if (t.isEmpty()) {
                continue;
            }
            if (!t.startsWith("data:")) {
                continue;
            }
            String payload = t.substring(5).trim();
            if (payload.isEmpty() || "[DONE]".equals(payload)) {
                continue;
            }
            String delta = extractDeltaTextFromJson(payload);
            if (delta == null) {
                continue;
            }
            if (out == null) {
                out = new StringBuilder(delta.length() + 16);
            }
            out.append(delta);
        }
        return out == null ? null : out.toString();
    }

    private static String extractDeltaTextFromJson(String json) {
        try {
            JSONObject obj = JSONUtil.parseObj(json);
            JSONArray choices = obj.getJSONArray("choices");
            if (choices == null || choices.isEmpty()) {
                return null;
            }
            JSONObject c0 = choices.getJSONObject(0);
            if (c0 == null) {
                return null;
            }
            JSONObject delta = c0.getJSONObject("delta");
            if (delta == null) {
                return null;
            }
            String content = delta.getStr("content");
            return content;
        } catch (Exception ignored) {
            return null;
        }
    }
}

