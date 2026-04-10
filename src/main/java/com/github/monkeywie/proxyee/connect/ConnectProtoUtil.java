package com.github.monkeywie.proxyee.connect;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static com.github.monkeywie.proxyee.intercept.cursor.CursorHttp2StreamAbortIntercept.firstNonBlank;

/**
 * gRPC Connect 流式响应与 Cursor StreamUnifiedChat protobuf 的公共解析工具。
 */
public final class ConnectProtoUtil {

    /** 与 Cursor 客户端一致的单帧 payload 上限（与 {@code CursorChatUtil} 原逻辑一致） */
    public static final int MAX_CONNECT_PAYLOAD_LEN = 4 * 1024 * 1024;

    private static final int WIRE_TYPE_VARINT = 0;
    private static final int WIRE_TYPE_LENGTH_DELIMITED = 2;
    private static final int WIRE_TYPE_FIXED64 = 1;
    private static final int WIRE_TYPE_FIXED32 = 5;

    private ConnectProtoUtil() {}

    /**
     * 在 {@code haystack} 中查找 {@code needle} 首次出现的字节下标；未找到返回 -1。
     */
    public static int indexOfSubsequence(byte[] haystack, byte[] needle) {
        if (haystack == null || needle == null || needle.length == 0) {
            return -1;
        }
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * 将「按字节截断」的 exclusive 下标收拢到合法 UTF-8 字符边界之前，避免半个码点导致下游解码异常。
     *
     * @return 最大 {@code e}（0≤e≤min(exclusiveEnd, bytes.length)），使 {@code bytes[0..e)} 为合法 UTF-8 前缀
     */
    public static int utf8SafeExclusiveEnd(byte[] bytes, int exclusiveEnd) {
        if (bytes == null || bytes.length == 0 || exclusiveEnd <= 0) {
            return 0;
        }
        if (exclusiveEnd > bytes.length) {
            exclusiveEnd = bytes.length;
        }
        int i = exclusiveEnd;
        while (i > 0 && (bytes[i - 1] & 0xC0) == 0x80) {
            i--;
        }
        if (i == 0) {
            return 0;
        }
        int leadIdx = i - 1;
        int b0 = bytes[leadIdx] & 0xFF;
        if (b0 < 0x80) {
            return exclusiveEnd;
        }
        int need;
        if ((b0 & 0xE0) == 0xC0) {
            need = 2;
        } else if ((b0 & 0xF0) == 0xE0) {
            need = 3;
        } else if ((b0 & 0xF8) == 0xF0) {
            need = 4;
        } else {
            return leadIdx;
        }
        if (exclusiveEnd - leadIdx >= need) {
            return exclusiveEnd;
        }
        return leadIdx;
    }

    /**
     * 在「单条顶层 protobuf 消息」内，将按字节的 exclusive 下标收拢到<strong>完整字段</strong>边界之前。
     * 若截断点落在某 length-delimited 字段载荷内部，则回退到该字段 tag 之前（不尝试重写嵌套子消息长度）。
     */
    public static int protobufWireSafeExclusiveEnd(byte[] data, int exclusiveEnd) {
        if (data == null || data.length == 0 || exclusiveEnd <= 0) {
            return 0;
        }
        int limit = Math.min(exclusiveEnd, data.length);
        int pos = 0;
        int lastGood = 0;
        while (pos < limit) {
            int fieldTagStart = pos;
            int[] tag = readTagBounded(data, pos, limit);
            if (tag == null) {
                return lastGood;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (fieldNumber == 0) {
                return lastGood;
            }
            switch (wireType) {
                case WIRE_TYPE_VARINT: {
                    int[] vv = readVarintBounded(data, pos, limit);
                    if (vv == null) {
                        return lastGood;
                    }
                    pos = vv[1];
                    break;
                }
                case WIRE_TYPE_FIXED64:
                    if (pos + 8 > limit) {
                        return lastGood;
                    }
                    pos += 8;
                    break;
                case WIRE_TYPE_LENGTH_DELIMITED: {
                    int[] lenRes = readVarintBounded(data, pos, limit);
                    if (lenRes == null) {
                        return lastGood;
                    }
                    int len = lenRes[0];
                    pos = lenRes[1];
                    if (len < 0) {
                        return lastGood;
                    }
                    int payloadEnd = pos + len;
                    if (payloadEnd < pos || payloadEnd > data.length || limit < payloadEnd) {
                        return lastGood;
                    }
                    pos = payloadEnd;
                    break;
                }
                case WIRE_TYPE_FIXED32:
                    if (pos + 4 > limit) {
                        return lastGood;
                    }
                    pos += 4;
                    break;
                default:
                    return lastGood;
            }
            if (fieldTagStart < limit) {
                lastGood = pos;
            }
        }
        return lastGood;
    }

    /**
     * 构造 [0, exclusiveEnd) 语义下<strong>线格式合法</strong>的 protobuf 前缀字节。
     * 截断点落在嵌套 length-delimited 载荷内时递归收缩子消息并<strong>重写该层长度</strong>，避免整段回退为 0 字节。
     */
    public static byte[] protobufSafePrefixBytes(byte[] data, int exclusiveEnd) {
        if (data == null || exclusiveEnd <= 0) {
            return new byte[0];
        }
        exclusiveEnd = Math.min(exclusiveEnd, data.length);
        return protobufSafePrefixBytesInner(data, exclusiveEnd);
    }

    private static byte[] protobufSafePrefixBytesInner(byte[] data, int exclusiveEnd) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(exclusiveEnd + 32, data.length + 16));
        int pos = 0;
        int limit = exclusiveEnd;
        while (pos < limit) {
            int fieldTagStart = pos;
            int[] tag = readTagBounded(data, pos, limit);
            if (tag == null) {
                break;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (fieldNumber == 0) {
                break;
            }
            switch (wireType) {
                case WIRE_TYPE_VARINT: {
                    int[] vv = readVarintBounded(data, pos, limit);
                    if (vv == null) {
                        return out.toByteArray();
                    }
                    out.write(data, fieldTagStart, vv[1] - fieldTagStart);
                    pos = vv[1];
                    break;
                }
                case WIRE_TYPE_FIXED64:
                    if (pos + 8 > limit) {
                        return out.toByteArray();
                    }
                    out.write(data, fieldTagStart, (pos + 8) - fieldTagStart);
                    pos += 8;
                    break;
                case WIRE_TYPE_LENGTH_DELIMITED: {
                    int[] lenRes = readVarintBounded(data, pos, limit);
                    if (lenRes == null) {
                        return out.toByteArray();
                    }
                    int len = lenRes[0];
                    int payloadStart = lenRes[1];
                    if (len < 0) {
                        return out.toByteArray();
                    }
                    int payloadEnd = payloadStart + len;
                    if (payloadEnd < payloadStart || payloadEnd > data.length) {
                        return out.toByteArray();
                    }
                    if (limit >= payloadEnd) {
                        out.write(data, fieldTagStart, payloadEnd - fieldTagStart);
                        pos = payloadEnd;
                    } else if (limit < payloadStart) {
                        return out.toByteArray();
                    } else {
                        int innerExclusive = limit - payloadStart;
                        byte[] innerSlice = Arrays.copyOfRange(data, payloadStart, payloadEnd);
                        byte[] innerPrefixPb = protobufSafePrefixBytesInner(innerSlice, innerExclusive);
                        int utf8End = utf8SafeExclusiveEnd(innerSlice, innerExclusive);
                        byte[] innerPrefixUtf8 = utf8End <= 0 ? new byte[0]
                                : Arrays.copyOfRange(innerSlice, 0, utf8End);
                        byte[] innerPrefix = innerPrefixPb;
                        // needle 常落在 UTF-8 文本字段内部：递归 protobuf 会把正文误解析为 tag，退成极短“安全”前缀，
                        // connect-es 收到畸形帧后既不吐字也不结束流。此时应优先按 UTF-8 码点截断 opaque 字符串体。
                        if (innerExclusive >= 32
                                && innerPrefixUtf8.length >= innerExclusive - 24
                                && innerPrefixPb.length < innerExclusive / 4) {
                            innerPrefix = innerPrefixUtf8;
                        }
                        writeTag(out, fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
                        writeVarint(out, innerPrefix.length);
                        out.write(innerPrefix, 0, innerPrefix.length);
                        return out.toByteArray();
                    }
                    break;
                }
                case WIRE_TYPE_FIXED32:
                    if (pos + 4 > limit) {
                        return out.toByteArray();
                    }
                    out.write(data, fieldTagStart, (pos + 4) - fieldTagStart);
                    pos += 4;
                    break;
                default:
                    return out.toByteArray();
            }
        }
        return out.toByteArray();
    }

    private static void writeTag(ByteArrayOutputStream out, int fieldNumber, int wireType) {
        writeVarint(out, (fieldNumber << 3) | wireType);
    }

    private static void writeVarint(ByteArrayOutputStream out, int value) {
        int v = value;
        while (true) {
            int b = v & 0x7F;
            v >>>= 7;
            if (v == 0) {
                out.write(b);
                return;
            }
            out.write(b | 0x80);
        }
    }

    /** @return {value, newPos} 或 null 表示 [pos,limit) 内 varint 不完整 */
    private static int[] readVarintBounded(byte[] data, int pos, int limit) {
        int result = 0;
        int shift = 0;
        int p = pos;
        while (p < limit && shift < 35) {
            int b = data[p++] & 0xFF;
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return new int[]{result, p};
            }
            shift += 7;
        }
        return null;
    }

    /** @return {fieldNumber, wireType, newPos} 或 null */
    private static int[] readTagBounded(byte[] data, int pos, int limit) {
        int[] v = readVarintBounded(data, pos, limit);
        if (v == null) {
            return null;
        }
        int tag = v[0];
        return new int[]{tag >>> 3, tag & 0x07, v[1]};
    }

    public static byte[] gzipDecompress(byte[] compressed) {
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream bos = new ByteArrayOutputStream(compressed.length * 2)) {
            byte[] buffer = new byte[4096];
            int len;
            while ((len = gis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    public static byte[] gzipCompress(byte[] raw) {
        if (raw == null) {
            return null;
        }
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(32, raw.length / 2));
             GZIPOutputStream gos = new GZIPOutputStream(bos)) {
            gos.write(raw);
            gos.finish();
            return bos.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 保持首字节中的 msgType/压缩标志，将解压后的载荷重新压回与 Connect 规范一致的 wire 帧。
     */
    public static byte[] recompressToConnectWire(byte[] originalWire, byte[] decompressedPayload) {
        if (originalWire == null || originalWire.length < 1) {
            return null;
        }
        if (decompressedPayload == null) {
            decompressedPayload = new byte[0];
        }
        int typeByte = originalWire[0] & 0xFF;
        boolean compressed = (typeByte & 1) != 0;
        byte[] payloadOut = compressed ? gzipCompress(decompressedPayload) : decompressedPayload;
        if (payloadOut == null) {
            return null;
        }
        if (payloadOut.length > MAX_CONNECT_PAYLOAD_LEN) {
            return null;
        }
        int len = payloadOut.length;
        byte[] out = new byte[5 + len];
        out[0] = originalWire[0];
        out[1] = (byte) ((len >> 24) & 0xFF);
        out[2] = (byte) ((len >> 16) & 0xFF);
        out[3] = (byte) ((len >> 8) & 0xFF);
        out[4] = (byte) (len & 0xFF);
        System.arraycopy(payloadOut, 0, out, 5, len);
        return out;
    }

    /**
     * 从 StreamUnifiedChatResponseWithTools protobuf 中提取文本（field 2 内嵌 message 的 field 1 text）。
     */
    public static String extractTextFromResponse(byte[] data) {
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
                        return extractTextField(data, pos, len);
                    }

                    pos += len;
                } else if (wireType == WIRE_TYPE_VARINT) {
                    int[] varintResult = readVarint(data, pos);
                    pos = varintResult[1];
                } else {
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * 在 {@link #extractTextFromResponse(byte[])} 基础上，对顶层各 length-delimited 子消息再递归解析或 UTF-8 可读串，
     * 覆盖 Agent/RunSSE 等与 UnifiedChat 字段布局不完全一致的响应。
     */
    public static String extractTextFromResponseLenient(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        String s = extractTextFromResponse(data);
        if (s != null && !s.isEmpty()) {
            return s;
        }
        return scanLengthDelimitedForAssistantText(data);
    }

    private static String scanLengthDelimitedForAssistantText(byte[] data) {
        String best = null;
        int bestLen = 0;
        try {
            int pos = 0;
            while (pos < data.length) {
                int[] tagResult = readTag(data, pos);
                int wireType = tagResult[1];
                pos = tagResult[2];

                if (wireType == WIRE_TYPE_LENGTH_DELIMITED) {
                    int[] lenResult = readVarint(data, pos);
                    int len = lenResult[0];
                    pos = lenResult[1];
                    if (len < 0 || pos + len > data.length) {
                        break;
                    }
                    byte[] chunk = Arrays.copyOfRange(data, pos, pos + len);
                    pos += len;
                    String inner = extractTextFromResponse(chunk);
                    if (inner != null && inner.length() > bestLen) {
                        best = inner;
                        bestLen = inner.length();
                    }
                    String cand = new String(chunk, StandardCharsets.UTF_8);
                    if (isLikelyAssistantUtf8(cand) && cand.length() > bestLen) {
                        best = cand;
                        bestLen = cand.length();
                    }
                } else if (wireType == WIRE_TYPE_VARINT) {
                    int[] varintResult = readVarint(data, pos);
                    pos = varintResult[1];
                } else if (wireType == WIRE_TYPE_FIXED64) {
                    pos += 8;
                } else if (wireType == WIRE_TYPE_FIXED32) {
                    pos += 4;
                } else {
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        return bestLen > 0 ? best : null;
    }

    /**
     * 仅提取 UnifiedChat 真正用户可见的 assistant 文本：
     * top-level 必须是 {@code StreamUnifiedChatResponseWithTools.response = stream_unified_chat_response}
     * 且内层必须存在 {@code StreamUnifiedChatResponse.text = 1}。
     */
    public static String extractVisibleTextFromUnifiedChatResponse(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        try {
            byte[] unified = extractLengthDelimitedFieldPayload(data, 2);
            if (unified == null || unified.length == 0) {
                return null;
            }
            return extractDelimitedStringField(unified, 1);
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * 用于调试桥接流：快速标记当前 UnifiedChat 帧属于文本、工具调用、thinking 还是其它事件。
     */
    public static String describeUnifiedChatResponseKind(byte[] data) {
        if (data == null || data.length == 0) {
            return "empty";
        }
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
                    if (len < 0 || pos + len > data.length) {
                        return "malformed";
                    }
                    byte[] chunk = Arrays.copyOfRange(data, pos, pos + len);
                    switch (fieldNumber) {
                        case 1:
                            return "client_side_tool_v2_call";
                        case 2:
                            return "stream_unified_chat_response:" + describeStreamUnifiedChatInnerKind(chunk);
                        case 3:
                            return "conversation_summary";
                        case 4:
                            return "user_rules";
                        case 5:
                            return "stream_start";
                        case 6:
                            return "tracing_context";
                        case 7:
                            return "event_id";
                        default:
                            return "top_level_field_" + fieldNumber;
                    }
                } else if (wireType == WIRE_TYPE_VARINT) {
                    int[] varintResult = readVarint(data, pos);
                    pos = varintResult[1];
                } else if (wireType == WIRE_TYPE_FIXED64) {
                    pos += 8;
                } else if (wireType == WIRE_TYPE_FIXED32) {
                    pos += 4;
                } else {
                    return "unknown_wire_type_" + wireType;
                }
            }
        } catch (Exception ignored) {
            return "parse_error";
        }
        return "no_response";
    }

    /**
     * 抽取 UnifiedChat 工具事件的轻量信息，便于运行时判断模型实际请求了什么工具。
     */
    public static String extractUnifiedChatToolCallSummary(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        try {
            byte[] unified = extractLengthDelimitedFieldPayload(data, 2);
            if (unified == null || unified.length == 0) {
                return null;
            }
            byte[] toolCall = extractLengthDelimitedFieldPayload(unified, 13);
            String source = "tool_call";
            if (toolCall == null || toolCall.length == 0) {
                toolCall = extractLengthDelimitedFieldPayload(unified, 36);
                source = "tool_call_v2";
            }
            if (toolCall == null || toolCall.length == 0) {
                byte[] partial = extractLengthDelimitedFieldPayload(unified, 15);
                if (partial != null && partial.length > 0) {
                    String toolName = firstNonBlank(
                            extractDelimitedStringField(partial, 3),
                            extractDelimitedStringField(partial, 2),
                            extractDelimitedStringField(partial, 1));
                    if (toolName != null) {
                        return "partial_tool_call:" + toolName;
                    }
                }
                return null;
            }
            String toolEnum = extractVarintFieldAsString(toolCall, 1);
            String toolCallId = extractDelimitedStringField(toolCall, 2);
            String name = extractDelimitedStringField(toolCall, 8);
            String rawArgs = firstNonBlank(
                    extractDelimitedStringField(toolCall, 10),
                    extractDelimitedStringField(toolCall, 9));
            StringBuilder sb = new StringBuilder();
            sb.append(source);
            if (name != null && !name.isEmpty()) {
                sb.append(":name=").append(name);
            }
            if (toolEnum != null && !toolEnum.isEmpty()) {
                sb.append(",tool=").append(toolEnum);
            }
            if (toolCallId != null && !toolCallId.isEmpty()) {
                sb.append(",callId=").append(toolCallId);
            }
            if (rawArgs != null && !rawArgs.isEmpty()) {
                sb.append(",rawArgs=").append(rawArgs);
            }
            return sb.toString();
        } catch (Exception ignored) {
            return null;
        }
    }

    /** 排除明显二进制垃圾，保留中英文等可打印正文（宽松）。 */
    private static boolean isLikelyAssistantUtf8(String s) {
        if (s == null) {
            return false;
        }
        int n = s.length();
        if (n < 1 || n > 512_000) {
            return false;
        }
        int bad = 0;
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c < 0x09) {
                bad += 2;
            } else if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
                bad++;
            }
        }
        return bad * 10 <= n * 3;
    }

    private static String describeStreamUnifiedChatInnerKind(byte[] data) {
        if (data == null || data.length == 0) {
            return "empty";
        }
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
                    if (len < 0 || pos + len > data.length) {
                        return "malformed";
                    }
                    switch (fieldNumber) {
                        case 1:
                            return "text";
                        case 2:
                            return "debugging_only_chat_prompt";
                        case 4:
                            return "document_citation";
                        case 5:
                            return "filled_prompt";
                        case 7:
                            return "intermediate_text";
                        case 8:
                            return "chunk_identity";
                        case 9:
                            return "docs_reference";
                        case 11:
                            return "web_citation";
                        case 12:
                            return "status_updates";
                        case 13:
                            return "tool_call";
                        case 15:
                            return "partial_tool_call";
                        case 16:
                            return "final_tool_result";
                        case 17:
                            return "symbol_link";
                        case 18:
                            return "conversation_summary";
                        case 19:
                            return "file_link";
                        case 20:
                            return "service_status_update";
                        case 21:
                            return "viewable_git_context";
                        case 23:
                            return "context_piece_update";
                        case 24:
                            return "used_code";
                        case 25:
                            return "thinking";
                        case 27:
                            return "usage_uuid";
                        case 28:
                            return "conversation_summary_starter";
                        case 29:
                            return "subagent_return";
                        case 30:
                            return "context_window_status";
                        case 31:
                            return "image_description";
                        case 34:
                            return "stars_feedback_request";
                        case 35:
                            return "model_provider_request_json";
                        case 36:
                            return "tool_call_v2";
                        case 37:
                            return "thinking_style";
                        default:
                            pos += len;
                            continue;
                    }
                } else if (wireType == WIRE_TYPE_VARINT) {
                    int[] varintResult = readVarint(data, pos);
                    pos = varintResult[1];
                } else if (wireType == WIRE_TYPE_FIXED64) {
                    pos += 8;
                } else if (wireType == WIRE_TYPE_FIXED32) {
                    pos += 4;
                } else {
                    return "unknown_wire_type_" + wireType;
                }
            }
        } catch (Exception ignored) {
            return "parse_error";
        }
        return "no_text";
    }

    private static String extractVarintFieldAsString(byte[] data, int targetFieldNumber) {
        if (data == null || data.length == 0) {
            return null;
        }
        int pos = 0;
        while (pos < data.length) {
            int[] tagResult = readTag(data, pos);
            int fieldNumber = tagResult[0];
            int wireType = tagResult[1];
            pos = tagResult[2];
            if (wireType == WIRE_TYPE_VARINT) {
                int[] varintResult = readVarint(data, pos);
                if (fieldNumber == targetFieldNumber) {
                    return Integer.toString(varintResult[0]);
                }
                pos = varintResult[1];
            } else if (wireType == WIRE_TYPE_LENGTH_DELIMITED) {
                int[] lenResult = readVarint(data, pos);
                int len = lenResult[0];
                pos = lenResult[1] + len;
            } else if (wireType == WIRE_TYPE_FIXED64) {
                pos += 8;
            } else if (wireType == WIRE_TYPE_FIXED32) {
                pos += 4;
            } else {
                return null;
            }
            if (pos < 0 || pos > data.length) {
                return null;
            }
        }
        return null;
    }

    private static byte[] extractLengthDelimitedFieldPayload(byte[] data, int targetFieldNumber) {
        if (data == null || data.length == 0) {
            return null;
        }
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
                if (len < 0 || pos + len > data.length) {
                    return null;
                }
                if (fieldNumber == targetFieldNumber) {
                    return Arrays.copyOfRange(data, pos, pos + len);
                }
                pos += len;
            } else if (wireType == WIRE_TYPE_VARINT) {
                int[] varintResult = readVarint(data, pos);
                pos = varintResult[1];
            } else if (wireType == WIRE_TYPE_FIXED64) {
                pos += 8;
            } else if (wireType == WIRE_TYPE_FIXED32) {
                pos += 4;
            } else {
                return null;
            }
        }
        return null;
    }

    private static String extractDelimitedStringField(byte[] data, int targetFieldNumber) {
        if (data == null || data.length == 0) {
            return null;
        }
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
                if (len < 0 || pos + len > data.length) {
                    return null;
                }
                if (fieldNumber == targetFieldNumber) {
                    return new String(data, pos, len, StandardCharsets.UTF_8);
                }
                pos += len;
            } else if (wireType == WIRE_TYPE_VARINT) {
                int[] varintResult = readVarint(data, pos);
                pos = varintResult[1];
            } else if (wireType == WIRE_TYPE_FIXED64) {
                pos += 8;
            } else if (wireType == WIRE_TYPE_FIXED32) {
                pos += 4;
            } else {
                return null;
            }
        }
        return null;
    }

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
                        return new String(data, pos, len, StandardCharsets.UTF_8);
                    }

                    pos += len;
                } else if (wireType == WIRE_TYPE_VARINT) {
                    int[] varintResult = readVarint(data, pos);
                    pos = varintResult[1];
                } else if (wireType == 1) {
                    pos += 8;
                } else if (wireType == 5) {
                    pos += 4;
                } else {
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

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

    private static int[] readTag(byte[] data, int pos) {
        int[] varintResult = readVarint(data, pos);
        int tag = varintResult[0];
        int fieldNumber = tag >>> 3;
        int wireType = tag & 0x07;
        return new int[]{fieldNumber, wireType, varintResult[1]};
    }
    /**
     * 从Connect wire帧中移除abort token，返回一个干净的、不包含abort token的Connect帧
     *
     * @param wire 原始Connect wire帧
     * @param needle abort token字节数组
     * @return 移除abort token后的Connect wire帧，如果移除失败则返回null
     */
    public static byte[] removeAbortTokenFromWire(byte[] wire, byte[] needle) {
        if (wire == null || wire.length < 5 || needle == null || needle.length == 0) {
            return null;
        }

        try {
            // 1. 解析Connect帧
            int typeByte = wire[0] & 0xFF;
            boolean compressed = (typeByte & 1) != 0;
            int msgType = (typeByte >> 1) & 0x03;

            // 2. 读取payload长度
            int payloadLength = ((wire[1] & 0xFF) << 24) |
                    ((wire[2] & 0xFF) << 16) |
                    ((wire[3] & 0xFF) << 8) |
                    (wire[4] & 0xFF);

            if (wire.length < 5 + payloadLength) {
                return null; // 帧不完整
            }

            // 3. 获取payload
            byte[] compressedPayload = Arrays.copyOfRange(wire, 5, 5 + payloadLength);
            byte[] decompressedPayload = compressed ? gzipDecompress(compressedPayload) : compressedPayload;

            if (decompressedPayload == null) {
                return null;
            }

            // 4. 在 payload 字节中查找 abort token（禁止用 String.indexOf：UTF-16 下标≠UTF-8 字节下标）
            int tokenByteIndex = indexOfSubsequence(decompressedPayload, needle);
            if (tokenByteIndex < 0) {
                return wire;
            }

            // 5–6. 在 token 起始字节前做 protobuf/UTF-8 安全前缀
            byte[] cleanPayload = protobufSafePrefixBytes(decompressedPayload, tokenByteIndex);

            // 7. 重新打包成Connect帧
            return recompressToConnectWire(wire, cleanPayload);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 从 Connect wire 帧解压出 payload 字节（与 {@link #removeAbortTokenFromWire} 解析一致）。
     */
    public static byte[] extractPayloadFromWire(byte[] wire) {
        if (wire == null || wire.length < 5) {
            return null;
        }
        try {
            int typeByte = wire[0] & 0xFF;
            boolean compressed = (typeByte & 1) != 0;
            int payloadLength = ((wire[1] & 0xFF) << 24)
                    | ((wire[2] & 0xFF) << 16)
                    | ((wire[3] & 0xFF) << 8)
                    | (wire[4] & 0xFF);
            if (payloadLength < 0 || wire.length < 5 + payloadLength) {
                return null;
            }
            byte[] raw = Arrays.copyOfRange(wire, 5, 5 + payloadLength);
            return compressed ? gzipDecompress(raw) : raw;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Cursor 流式帧内常内嵌 JSON 对话；abort token 若出现在 user/system 规则、思考说明里会误触发截断。
     * 仅在 needle 之前最近一次 {@code "role":"..."} 为 {@code assistant} 时返回 true（应执行 abort）。
     */
    public static boolean lastRoleBeforeNeedleIsAssistant(byte[] utf8PrefixBeforeNeedle) {
        if (utf8PrefixBeforeNeedle == null || utf8PrefixBeforeNeedle.length == 0) {
            return true;
        }
        String s = new String(utf8PrefixBeforeNeedle, StandardCharsets.UTF_8);
        int u = s.lastIndexOf("\"role\":\"user\"");
        int a = s.lastIndexOf("\"role\":\"assistant\"");
        int sys = s.lastIndexOf("\"role\":\"system\"");
        int max = Math.max(Math.max(u, a), sys);
        if (max < 0) {
            return true;
        }
        return max == a;
    }
}
