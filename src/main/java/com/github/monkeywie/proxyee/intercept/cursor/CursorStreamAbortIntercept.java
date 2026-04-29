package com.github.monkeywie.proxyee.intercept.cursor;

import com.github.monkeywie.proxyee.connect.ConnectProtoUtil;
import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.codec.http.HttpContentDecompressor;
import io.netty.util.AttributeKey;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 纯观测拦截器：只记录 RunSSE/BidiAppend 的请求响应数据流，不做任何 abort/截断。
 */
public class CursorStreamAbortIntercept extends HttpProxyIntercept {

    private static final Logger LOG = Logger.getLogger(CursorStreamAbortIntercept.class.getName());
    private static final String FILE_LOG_PATH = "logs/cursor-stream-abort.log";
    private static final ConcurrentHashMap<String, AtomicInteger> REQUEST_ID_SEEN = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, AtomicInteger> SESSION_ID_SEEN = new ConcurrentHashMap<>();
    private static final AttributeKey<AtomicInteger> REQUEST_SEQ_KEY =
            AttributeKey.valueOf("cursorStreamTraceReqSeq");
    private static final AttributeKey<CursorTraceState> STATE =
            AttributeKey.valueOf("cursorStreamTraceState");
    private static final Pattern JSON_TEXT_PATTERN = Pattern.compile("\"text\"\\s*:\\s*\"(.*?)\"");
    private static final Pattern HEX_RUN_PATTERN = Pattern.compile("[0-9a-fA-F]{64,}");
    private static final Pattern HEX_TEXT_RUN_PATTERN = Pattern.compile("[0-9a-fA-F]{32,}");
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final String Q_CN_WHO = "你是谁";
    private static final String Q_CN_CAN = "你能做什么";
    private static final String Q_CN_WHO_UTF8_HEX = "e4bda0e698afe8b081";
    private static final String Q_CN_CAN_UTF8_HEX = "e4bda0e883bde5819ae4bb80e4b988";
    private static final String DEBUG_LOG_PATH = "debug-73ba2f.log";
    private static final String DEBUG_SESSION_ID = "73ba2f";

    static {
        initFileLogger();
    }

    @Override
    public void beforeRequest(Channel clientChannel, HttpRequest httpRequest,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        String normalizedUri = normalizePathOnly(httpRequest.uri());
        if (!isObservedUri(normalizedUri)) {
            clientChannel.attr(STATE).remove();
            pipeline.beforeRequest(clientChannel, httpRequest);
            return;
        }

        CursorTraceState st = new CursorTraceState();
        st.clientChannelId = safeChannelId(clientChannel);
        st.requestSeqOnChannel = nextRequestSeq(clientChannel);
        st.requestMethod = httpRequest.method().name();
        st.requestUri = httpRequest.uri();
        st.normalizedUri = normalizedUri;
        st.uriClass = classifyUri(normalizedUri);
        st.requestId = headerFirstIgnoreCase(httpRequest.headers(), "x-request-id");
        st.sessionId = headerFirstIgnoreCase(httpRequest.headers(), "x-session-id");
        st.keepAlive = HttpUtil.isKeepAlive(httpRequest);
        clientChannel.attr(STATE).set(st);

        LOG.info(() -> String.format("[CursorAbort] monitor response for uri=%s uriClass=%s",
                httpRequest.uri(), st.uriClass));
        // #region agent log
        debugLog("pre-fix", "H4", "CursorStreamAbortIntercept.beforeRequest(HttpRequest)",
                "observed_uri_request_started",
                "{\"uri\":\"" + esc(st.requestUri) + "\",\"uriClass\":\"" + esc(st.uriClass)
                        + "\",\"requestId\":\"" + esc(valueOrDash(st.requestId))
                        + "\",\"sessionId\":\"" + esc(valueOrDash(st.sessionId)) + "\"}");
        // #endregion
        logRequest(httpRequest, st);
        pipeline.beforeRequest(clientChannel, httpRequest);
    }

    @Override
    public void beforeRequest(Channel clientChannel, HttpContent httpContent,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        CursorTraceState st = clientChannel.attr(STATE).get();
        if (st != null) {
            ByteBuf content = httpContent.content();
            byte[] bytes = new byte[content.readableBytes()];
            content.getBytes(content.readerIndex(), bytes);
            st.requestChunkIndex++;
            if (bytes.length > 0) {
                st.requestBodyBuffer.write(bytes);
            }

            String kind = (httpContent instanceof LastHttpContent) ? "last" : "chunk";
            String log = "[CursorAbort] request " + kind + " #" + st.requestChunkIndex
                    + " for " + requestKey(st)
                    + "\ntrace:"
                    + "\n  uriClass=" + st.uriClass
                    + "\n  clientChannelId=" + valueOrDash(st.clientChannelId)
                    + "\n  requestSeqOnChannel=" + st.requestSeqOnChannel
                    + " (" + bytes.length + " bytes)"
                    + "\nrequest-chunk-body:\n" + renderRequestChunkBody(st, bytes);
            LOG.info(log);
            if (httpContent instanceof LastHttpContent) {
                // #region agent log
                debugLog("pre-fix", "H3", "CursorStreamAbortIntercept.beforeRequest(HttpContent)",
                        "request_body_collected",
                        "{\"uriClass\":\"" + esc(st.uriClass) + "\",\"requestChunks\":" + st.requestChunkIndex
                                + ",\"requestBodyBytes\":" + st.requestBodyBuffer.size() + "}");
                // #endregion
                logRequestBodySummary(st);
            }
        }
        pipeline.beforeRequest(clientChannel, httpContent);
    }

    @Override
    public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        CursorTraceState st = clientChannel.attr(STATE).get();
        if (st == null) {
            pipeline.afterResponse(clientChannel, proxyChannel, httpResponse);
            return;
        }
        st.httpResponse = httpResponse;
        st.proxyChannelId = safeChannelId(proxyChannel);
        logResponseHeaders(httpResponse, st);
        ensureGzipDecompressor(proxyChannel, httpResponse, st);
        pipeline.afterResponse(clientChannel, proxyChannel, httpResponse);
    }

    @Override
    public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        CursorTraceState st = clientChannel.attr(STATE).get();
        if (st == null) {
            pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
            return;
        }

        ByteBuf buf = httpContent.content();
        int n = buf.readableBytes();
        if (n == 0) {
            if (httpContent instanceof LastHttpContent) {
                logResponseBodySummary(st);
            }
            pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
            return;
        }

        byte[] chunk = new byte[n];
        buf.getBytes(buf.readerIndex(), chunk);
        st.responseChunkIndex++;
        logResponseChunk(st, chunk);
        st.responseBodyBuffer.write(chunk);
        if (httpContent instanceof LastHttpContent) {
            logResponseBodySummary(st);
        }
        pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
    }

    private void ensureGzipDecompressor(Channel proxyChannel, HttpResponse httpResponse, CursorTraceState st) {
        if (st.decompressorAdded) {
            return;
        }
        if (!isGzipResponse(httpResponse)) {
            return;
        }
        if (httpResponse.headers().get(HttpHeaderNames.CONTENT_ENCODING) == null) {
            String cce = httpResponse.headers().get("connect-content-encoding");
            if (cce != null && cce.toLowerCase().contains("gzip")) {
                httpResponse.headers().set(HttpHeaderNames.CONTENT_ENCODING, "gzip");
                LOG.info("[CursorAbort] mapped connect-content-encoding to Content-Encoding for decompressor");
            }
        }
        if (proxyChannel.pipeline().get("cursorDecompress") == null) {
            proxyChannel.pipeline().addAfter("httpCodec", "cursorDecompress", new HttpContentDecompressor());
            st.decompressorAdded = true;
            LOG.info("[CursorAbort] inserted HttpContentDecompressor on upstream pipeline");
        }
    }

    private static boolean isGzipResponse(HttpResponse r) {
        String ce = r.headers().get(HttpHeaderNames.CONTENT_ENCODING);
        if (ce != null && ce.toLowerCase().contains("gzip")) {
            return true;
        }
        String cce = r.headers().get("connect-content-encoding");
        return cce != null && cce.toLowerCase().contains("gzip");
    }

    private static void initFileLogger() {
        try {
            Path logPath = Paths.get(FILE_LOG_PATH);
            Path parent = logPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            FileHandler fileHandler = new FileHandler(FILE_LOG_PATH, true);
            fileHandler.setEncoding(StandardCharsets.UTF_8.name());
            fileHandler.setFormatter(new PlainLogFormatter());
            LOG.addHandler(fileHandler);
            LOG.setUseParentHandlers(true);
            LOG.info("[CursorAbort] file logging enabled at " + logPath.toAbsolutePath());
        } catch (Exception e) {
            LOG.log(Level.WARNING, "[CursorAbort] failed to initialize file logger", e);
        }
    }

    private void logRequest(HttpRequest request, CursorTraceState st) {
        int reqSeen = seenCount(REQUEST_ID_SEEN, st.requestId);
        int sessSeen = seenCount(SESSION_ID_SEEN, st.sessionId);
        StringBuilder sb = new StringBuilder();
        sb.append("[CursorAbort] request ")
                .append(request.method())
                .append(" ")
                .append(request.uri())
                .append("\ntrace:")
                .append("\n  clientChannelId=").append(st.clientChannelId)
                .append("\n  requestSeqOnChannel=").append(st.requestSeqOnChannel)
                .append("\n  keepAlive=").append(st.keepAlive)
                .append("\n  x-request-id=").append(valueOrDash(st.requestId))
                .append("\n  x-request-id-seen=").append(reqSeen)
                .append("\n  x-session-id=").append(valueOrDash(st.sessionId))
                .append("\n  x-session-id-seen=").append(sessSeen)
                .append("\n  uriClass=").append(valueOrDash(st.uriClass))
                .append("\nheaders:\n")
                .append(headersToString(request.headers()));
        LOG.info(sb::toString);
    }

    private void logResponseHeaders(HttpResponse response, CursorTraceState st) {
        String log = "[CursorAbort] response for " + requestKey(st)
                + "\nstatus: " + response.status()
                + "\ntrace:"
                + "\n  clientChannelId=" + valueOrDash(st.clientChannelId)
                + "\n  proxyChannelId=" + valueOrDash(st.proxyChannelId)
                + "\n  requestSeqOnChannel=" + st.requestSeqOnChannel
                + "\n  x-request-id=" + valueOrDash(st.requestId)
                + "\n  x-session-id=" + valueOrDash(st.sessionId)
                + "\n  uriClass=" + valueOrDash(st.uriClass)
                + "\nheaders:\n" + headersToString(response.headers());
        LOG.info(log);
    }

    private void logResponseChunk(CursorTraceState st, byte[] chunk) {
        String log = "[CursorAbort] response chunk #" + st.responseChunkIndex + " for " + requestKey(st)
                + " (" + chunk.length + " bytes)"
                + "\nchunk-body:\n" + fullUtf8(chunk);
        LOG.info(log);
    }

    private void logRequestBodySummary(CursorTraceState st) {
        byte[] body = st.requestBodyBuffer.toByteArray();
        StringBuilder sb = new StringBuilder();
        sb.append("[CursorAbort] request body summary for ").append(requestKey(st))
                .append("\ntrace:")
                .append("\n  uriClass=").append(valueOrDash(st.uriClass))
                .append("\n  totalBodyBytes=").append(body.length);
        appendConnectAndProtoSummary(sb, body, st.uriClass, true);
        LOG.info(sb::toString);
    }

    private void logResponseBodySummary(CursorTraceState st) {
        byte[] body = st.responseBodyBuffer.toByteArray();
        StringBuilder sb = new StringBuilder();
        sb.append("[CursorAbort] response body summary for ").append(requestKey(st))
                .append("\ntrace:")
                .append("\n  uriClass=").append(valueOrDash(st.uriClass))
                .append("\n  totalBodyBytes=").append(body.length);
        appendConnectAndProtoSummary(sb, body, st.uriClass, false);
        LOG.info(sb::toString);
    }

    private static void appendConnectAndProtoSummary(
            StringBuilder sb, byte[] body, String uriClass, boolean requestSide) {
        sb.append("\nraw-utf8:\n").append(fullUtf8(body));
        if ("BidiAppend".equals(uriClass)) {
            sb.append("\nwire-hex:\n").append(toHex(body));
        }
        if (body == null || body.length == 0) {
            return;
        }
        DecodedPayload decoded = decodePayloadForLogging(body);
        sb.append("\nframe-decode:")
                .append("\n  mode=").append(decoded.mode)
                .append("\n  payloadDecode=").append(decoded.payload == null ? "failed" : "ok")
                .append("\n  wireLen=").append(body.length);
        if (decoded.mode.startsWith("connect")) {
            sb.append("\n  typeByte=").append(decoded.typeByte)
                    .append("\n  compressed=").append(decoded.compressed)
                    .append("\n  payloadLen=").append(decoded.payloadLen);
        }
        byte[] payload = decoded.payload;
        if (payload == null) {
            return;
        }
        sb.append("\n  payloadDecode=ok")
                .append("\n  payloadUtf8:\n").append(fullUtf8(payload));
        if ("BidiAppend".equals(uriClass)) {
            sb.append("\n  payloadHex:\n").append(toHex(payload));
        }
        String textCandidate = extractTextCandidate(payload);
        if (textCandidate != null && !textCandidate.isEmpty()) {
            sb.append("\n  decodedTextPreview:\n").append(textCandidate);
        }
        String kind = requestSide
                ? ConnectProtoUtil.describeAgentServerMessageKind(payload)
                : ConnectProtoUtil.describeUnifiedChatResponseKind(payload);
        sb.append("\n  protobufKind=").append(kind);
        if ("BidiAppend".equals(uriClass)) {
            String visible = requestSide
                    ? ConnectProtoUtil.extractVisibleTextFromAgentServerMessage(payload)
                    : ConnectProtoUtil.extractVisibleTextFromUnifiedChatResponse(payload);
            if (visible != null && !visible.trim().isEmpty()) {
                sb.append("\n  protobufVisibleText:\n").append(visible.trim());
            }
            String lenient = ConnectProtoUtil.extractTextFromResponseLenient(payload);
            if (lenient != null && !lenient.trim().isEmpty()) {
                sb.append("\n  protobufLenientText:\n").append(lenient.trim());
            }
            List<String> candidates = extractReadableProtoStrings(payload);
            if (!candidates.isEmpty()) {
                sb.append("\n  protobufReadableStrings:");
                for (int i = 0; i < candidates.size(); i++) {
                    sb.append("\n    - ").append(candidates.get(i));
                }
            }
            String decodedPlaintext = buildHexDecodedPlaintextSummary(payload, candidates);
            if (!decodedPlaintext.isEmpty()) {
                sb.append("\n  wireHexDecodedPlaintext:\n").append(decodedPlaintext);
            }
            if (requestSide) {
                String plainParams = buildBidiAppendPlaintextParams(payload);
                if (plainParams != null && !plainParams.isEmpty()) {
                    sb.append("\n  bidiappendPlaintextParams:\n").append(plainParams);
                }
                // #region agent log
                debugLog("pre-fix", "H1", "CursorStreamAbortIntercept.appendConnectAndProtoSummary",
                        "bidiappend_request_plaintext_extraction",
                        "{\"decodeMode\":\"" + esc(decoded.mode) + "\""
                                + ",\"payloadLen\":" + payload.length
                                + ",\"visibleTextLen\":" + safeLen(visible)
                                + ",\"lenientTextLen\":" + safeLen(lenient)
                                + ",\"readableCount\":" + candidates.size()
                                + ",\"plainParamsLen\":" + safeLen(plainParams) + "}");
                debugLog("pre-fix", "H6", "CursorStreamAbortIntercept.appendConnectAndProtoSummary",
                        "bidiappend_request_question_presence_probe",
                        "{\"decodeMode\":\"" + esc(decoded.mode) + "\""
                                + ",\"payloadLen\":" + payload.length
                                + ",\"hasCnWho\":" + containsUtf8(payload, Q_CN_WHO)
                                + ",\"hasCnCan\":" + containsUtf8(payload, Q_CN_CAN)
                                + ",\"hasCnWhoHexAscii\":" + containsAsciiHex(payload, Q_CN_WHO_UTF8_HEX)
                                + ",\"hasCnCanHexAscii\":" + containsAsciiHex(payload, Q_CN_CAN_UTF8_HEX)
                                + "}");
                // #endregion
            }
        } else if ("RunSSE".equals(uriClass) && !requestSide) {
            String visibleText = ConnectProtoUtil.extractVisibleTextFromAgentServerMessage(payload);
            String lenientText = ConnectProtoUtil.extractTextFromResponseLenient(payload);
            // #region agent log
            debugLog("pre-fix", "H2", "CursorStreamAbortIntercept.appendConnectAndProtoSummary",
                    "runsse_response_text_extraction",
                    "{\"decodeMode\":\"" + esc(decoded.mode) + "\""
                            + ",\"payloadLen\":" + payload.length
                            + ",\"visibleTextLen\":" + safeLen(visibleText)
                            + ",\"lenientTextLen\":" + safeLen(lenientText)
                            + ",\"toolSummaryPresent\":" + (ConnectProtoUtil.extractUnifiedChatToolCallSummary(payload) != null) + "}");
            // #endregion
        }
        String toolSummary = ConnectProtoUtil.extractUnifiedChatToolCallSummary(payload);
        if (toolSummary != null && !toolSummary.trim().isEmpty()) {
            sb.append("\n  toolCallSummary=").append(toolSummary.trim());
        }
    }

    private static String extractTextCandidate(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }
        String utf8 = fullUtf8(payload);
        String fromJson = firstJsonTextField(utf8);
        if (fromJson != null) {
            return fromJson;
        }
        String fromHexWrapped = extractTextFromHexWrappedJson(utf8);
        if (fromHexWrapped != null) {
            return fromHexWrapped;
        }
        return utf8;
    }

    private static String renderRequestChunkBody(CursorTraceState st, byte[] currentChunk) {
        if (!"BidiAppend".equals(st.uriClass)) {
            return fullUtf8(currentChunk);
        }
        byte[] whole = st.requestBodyBuffer.toByteArray();
        String decoded = decodeBidiAppendPlaintext(whole);
        if (decoded != null && !decoded.trim().isEmpty()) {
            return decoded;
        }
        return "(bidiappend payload is binary/compressed; waiting for full frame to decode)";
    }

    private static String decodeBidiAppendPlaintext(byte[] wire) {
        if (wire == null || wire.length < 5) {
            return null;
        }
        byte[] payload = ConnectProtoUtil.extractPayloadFromWire(wire);
        if (payload == null || payload.length == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("connect-payload-utf8:\n").append(fullUtf8(payload));
        String visible = ConnectProtoUtil.extractVisibleTextFromAgentServerMessage(payload);
        if (visible != null && !visible.trim().isEmpty()) {
            sb.append("\nprotobuf-visible-text:\n").append(visible.trim());
        }
        String lenient = ConnectProtoUtil.extractTextFromResponseLenient(payload);
        if (lenient != null && !lenient.trim().isEmpty()) {
            sb.append("\nprotobuf-lenient-text:\n").append(lenient.trim());
        }
        String candidate = extractTextCandidate(payload);
        if (candidate != null && !candidate.trim().isEmpty()) {
            sb.append("\ndecoded-text-preview:\n").append(candidate.trim());
        }
        return sb.toString();
    }

    private static String firstJsonTextField(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        Matcher m = JSON_TEXT_PATTERN.matcher(s);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    private static String extractTextFromHexWrappedJson(String view) {
        if (view == null || view.isEmpty()) {
            return null;
        }
        Matcher m = HEX_RUN_PATTERN.matcher(view);
        while (m.find()) {
            String hex = m.group();
            if ((hex.length() & 1) == 1) {
                continue;
            }
            byte[] decoded = tryDecodeHexToBytes(hex);
            if (decoded == null || decoded.length == 0) {
                continue;
            }
            String candidate = firstJsonTextField(fullUtf8(decoded));
            if (candidate != null && !candidate.trim().isEmpty()) {
                return candidate.trim();
            }
        }
        return null;
    }

    private static byte[] tryDecodeHexToBytes(String hex) {
        try {
            int n = hex.length();
            byte[] out = new byte[n / 2];
            for (int i = 0; i < n; i += 2) {
                int hi = Character.digit(hex.charAt(i), 16);
                int lo = Character.digit(hex.charAt(i + 1), 16);
                if (hi < 0 || lo < 0) {
                    return null;
                }
                out[i / 2] = (byte) ((hi << 4) + lo);
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    private static String toHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0x0F, 16));
            sb.append(Character.forDigit(b & 0x0F, 16));
        }
        return sb.toString();
    }

    /**
     * 纯 Java protobuf wire 扫描：递归提取 length-delimited 中可读 UTF-8 字符串。
     */
    private static List<String> extractReadableProtoStrings(byte[] protobuf) {
        List<String> out = new ArrayList<>();
        collectReadableProtoStrings(protobuf, 0, 0, out);
        return out;
    }

    private static void collectReadableProtoStrings(byte[] data, int offset, int depth, List<String> out) {
        if (data == null || data.length == 0 || depth > 4 || out.size() >= 24) {
            return;
        }
        int pos = offset;
        while (pos < data.length && out.size() < 24) {
            int[] tagRes = readVarint(data, pos);
            if (tagRes == null) {
                return;
            }
            int tag = tagRes[0];
            pos = tagRes[1];
            int wireType = tag & 0x07;
            if (wireType == 2) {
                int[] lenRes = readVarint(data, pos);
                if (lenRes == null) {
                    return;
                }
                int len = lenRes[0];
                pos = lenRes[1];
                if (len < 0 || pos + len > data.length) {
                    return;
                }
                byte[] payload = new byte[len];
                System.arraycopy(data, pos, payload, 0, len);
                pos += len;

                String s = new String(payload, StandardCharsets.UTF_8).trim();
                if (isReadableTextCandidate(s)) {
                    if (!out.contains(s)) {
                        out.add(s);
                    }
                }
                // 递归尝试把 payload 当作嵌套 protobuf 继续提取
                collectReadableProtoStrings(payload, 0, depth + 1, out);
            } else if (wireType == 0) {
                int[] v = readVarint(data, pos);
                if (v == null) {
                    return;
                }
                pos = v[1];
            } else if (wireType == 1) {
                pos += 8;
            } else if (wireType == 5) {
                pos += 4;
            } else {
                return;
            }
            if (pos < 0 || pos > data.length) {
                return;
            }
        }
    }

    private static int[] readVarint(byte[] data, int pos) {
        int result = 0;
        int shift = 0;
        while (pos < data.length && shift < 35) {
            int b = data[pos++] & 0xFF;
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return new int[]{result, pos};
            }
            shift += 7;
        }
        return null;
    }

    private static boolean isReadableTextCandidate(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        if (s.length() < 3) {
            return false;
        }
        int bad = 0;
        int printable = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t') {
                bad++;
            } else {
                printable++;
            }
        }
        if (printable == 0 || bad * 3 > s.length()) {
            return false;
        }
        return s.contains("check_messages")
                || s.contains("my-mcp-1")
                || s.contains("tool")
                || s.contains("role")
                || s.contains("user")
                || s.contains("assistant")
                || s.contains("{")
                || s.matches(".*[\\u4e00-\\u9fff].*")
                || s.length() > 16;
    }

    private static String buildBidiAppendPlaintextParams(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        String kind = ConnectProtoUtil.describeAgentServerMessageKind(payload);
        sb.append("kind=").append(kind);

        String visible = ConnectProtoUtil.extractVisibleTextFromAgentServerMessage(payload);
        if (visible != null && !visible.trim().isEmpty()) {
            sb.append("\nvisibleText=").append(singleLine(visible));
        }
        String lenient = ConnectProtoUtil.extractTextFromResponseLenient(payload);
        if (lenient != null && !lenient.trim().isEmpty() && !looksLikeUuid(lenient.trim())) {
            sb.append("\nlenientText=").append(singleLine(lenient));
        }

        List<String> readable = extractReadableProtoStrings(payload);
        int matched = 0;
        for (int i = 0; i < readable.size() && matched < 16; i++) {
            String line = singleLine(readable.get(i));
            String decodedHexLine = decodeEmbeddedHexLine(line);
            if (isLikelyParamLine(line)) {
                sb.append("\nparam[").append(matched + 1).append("]=").append(line);
                matched++;
            } else if (decodedHexLine != null && isLikelyParamLine(decodedHexLine)) {
                sb.append("\nparam[").append(matched + 1).append("]=").append(decodedHexLine);
                matched++;
            }
        }
        // #region agent log
        debugLog("pre-fix", "H5", "CursorStreamAbortIntercept.buildBidiAppendPlaintextParams",
                "bidiappend_candidate_lines",
                "{\"readableCount\":" + readable.size()
                        + ",\"matchedCount\":" + matched
                        + ",\"sample\":\"" + esc(sampleLines(readable, 6)) + "\"}");
        // #endregion
        return sb.toString();
    }

    private static boolean isLikelyParamLine(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        String low = s.toLowerCase();
        return low.contains("check_messages")
                || low.contains("my-mcp-1")
                || low.contains("\"role\"")
                || low.contains("\"toolname\"")
                || low.contains("\"args\"")
                || low.contains("\"requestid\"")
                || low.contains("\"reply\"")
                || low.contains("<user_query>")
                || low.contains("tool-call")
                || low.contains("?")
                || low.contains("who are you")
                || low.contains("what can you do")
                || s.matches(".*[\\u4e00-\\u9fff].*");
    }

    private static String singleLine(String s) {
        if (s == null) {
            return "";
        }
        String one = s.replace('\n', ' ').replace('\r', ' ').trim();
        if (one.length() > 1200) {
            return one.substring(0, 1200) + "...";
        }
        return one;
    }

    private static boolean looksLikeUuid(String s) {
        if (s == null) {
            return false;
        }
        return UUID_PATTERN.matcher(s.trim()).matches();
    }

    private static String sampleLines(List<String> lines, int max) {
        if (lines == null || lines.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int n = Math.min(max, lines.size());
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append(" | ");
            }
            sb.append(singleLine(lines.get(i)));
        }
        return sb.toString();
    }

    private static String decodeEmbeddedHexLine(String line) {
        if (line == null) {
            return null;
        }
        String compact = line.replace(" ", "");
        if (compact.length() < 64 || (compact.length() & 1) == 1) {
            return null;
        }
        if (!compact.matches("(?i)[0-9a-f]+")) {
            return null;
        }
        byte[] decoded = tryDecodeHexToBytes(compact);
        if (decoded == null || decoded.length == 0) {
            return null;
        }
        String s = new String(decoded, StandardCharsets.UTF_8).trim();
        return s.isEmpty() ? null : singleLine(s);
    }

    private static String buildHexDecodedPlaintextSummary(byte[] payload, List<String> readableCandidates) {
        List<String> lines = new ArrayList<>();
        collectHexDecodedLines(lines, fullUtf8(payload));
        if (readableCandidates != null) {
            for (int i = 0; i < readableCandidates.size(); i++) {
                collectHexDecodedLines(lines, readableCandidates.get(i));
            }
        }
        if (lines.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(16, lines.size());
        for (int i = 0; i < limit; i++) {
            if (i > 0) {
                sb.append('\n');
            }
            sb.append("- ").append(lines.get(i));
        }
        if (lines.size() > limit) {
            sb.append("\n- ... (").append(lines.size() - limit).append(" more)");
        }
        return sb.toString();
    }

    private static void collectHexDecodedLines(List<String> out, String text) {
        if (text == null || text.isEmpty() || out.size() >= 32) {
            return;
        }
        Matcher m = HEX_TEXT_RUN_PATTERN.matcher(text);
        while (m.find() && out.size() < 32) {
            String hex = m.group();
            if ((hex.length() & 1) == 1) {
                continue;
            }
            byte[] decoded = tryDecodeHexToBytes(hex);
            if (decoded == null || decoded.length == 0) {
                continue;
            }
            String normalized = normalizeDecodedText(decoded);
            if (isMeaningfulDecodedLine(normalized) && !out.contains(normalized)) {
                out.add(normalized);
            }
        }
    }

    private static String normalizeDecodedText(byte[] bytes) {
        String raw = new String(bytes, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t') {
                continue;
            }
            sb.append(c);
        }
        String oneLine = singleLine(sb.toString());
        return oneLine.replace("\\\\", "\\");
    }

    private static boolean isMeaningfulDecodedLine(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        String low = s.toLowerCase();
        if (s.length() < 8) {
            return false;
        }
        return low.contains(".json")
                || low.contains("mcps")
                || low.contains("tool")
                || low.contains("ask_question")
                || low.contains("check_messages")
                || low.contains("send_message")
                || low.contains("project-")
                || low.contains("user-playwright")
                || low.contains("cursor")
                || low.contains("\\")
                || s.matches(".*[\\u4e00-\\u9fff].*");
    }

    private static boolean containsUtf8(byte[] bytes, String needle) {
        if (bytes == null || bytes.length == 0 || needle == null || needle.isEmpty()) {
            return false;
        }
        try {
            return new String(bytes, StandardCharsets.UTF_8).contains(needle);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean containsAsciiHex(byte[] bytes, String needleHexLower) {
        if (bytes == null || bytes.length == 0 || needleHexLower == null || needleHexLower.isEmpty()) {
            return false;
        }
        try {
            String s = new String(bytes, StandardCharsets.UTF_8).toLowerCase();
            return s.contains(needleHexLower.toLowerCase());
        } catch (Exception e) {
            return false;
        }
    }

    private static DecodedPayload decodePayloadForLogging(byte[] body) {
        DecodedPayload out = new DecodedPayload();
        if (body == null || body.length == 0) {
            out.mode = "empty";
            return out;
        }
        // 1) Gzip raw protobuf (BidiAppend 常见)
        if (isGzipMagic(body)) {
            out.mode = "raw-gzip-protobuf";
            out.payload = ConnectProtoUtil.gzipDecompress(body);
            return out;
        }
        // 2) Connect frame（RunSSE 常见）
        if (looksLikeConnectFrame(body)) {
            out.mode = "connect-frame";
            out.typeByte = body[0] & 0xFF;
            out.compressed = (out.typeByte & 1) != 0;
            out.payloadLen = ((body[1] & 0xFF) << 24)
                    | ((body[2] & 0xFF) << 16)
                    | ((body[3] & 0xFF) << 8)
                    | (body[4] & 0xFF);
            out.payload = ConnectProtoUtil.extractPayloadFromWire(body);
            return out;
        }
        // 3) Raw protobuf
        out.mode = "raw-protobuf";
        out.payload = body;
        return out;
    }

    private static boolean looksLikeConnectFrame(byte[] body) {
        if (body == null || body.length < 5) {
            return false;
        }
        int typeByte = body[0] & 0xFF;
        // Connect 的第 1 字节低位是压缩标记，其它位通常较小；BidiAppend raw protobuf 常见是 0x0a。
        if (typeByte > 3) {
            return false;
        }
        int payloadLen = ((body[1] & 0xFF) << 24)
                | ((body[2] & 0xFF) << 16)
                | ((body[3] & 0xFF) << 8)
                | (body[4] & 0xFF);
        return payloadLen >= 0 && payloadLen <= body.length - 5;
    }

    private static boolean isGzipMagic(byte[] body) {
        return body != null && body.length >= 2
                && (body[0] & 0xFF) == 0x1f
                && (body[1] & 0xFF) == 0x8b;
    }

    private static void debugLog(String runId, String hypothesisId, String location, String message, String dataJson) {
        try {
            String line = "{\"sessionId\":\"" + DEBUG_SESSION_ID + "\""
                    + ",\"runId\":\"" + esc(runId) + "\""
                    + ",\"hypothesisId\":\"" + esc(hypothesisId) + "\""
                    + ",\"location\":\"" + esc(location) + "\""
                    + ",\"message\":\"" + esc(message) + "\""
                    + ",\"data\":" + (dataJson == null ? "{}" : dataJson)
                    + ",\"timestamp\":" + System.currentTimeMillis()
                    + "}\n";
            Files.write(Paths.get(DEBUG_LOG_PATH), line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {
        }
    }

    private static int safeLen(String s) {
        return s == null ? 0 : s.length();
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static final class DecodedPayload {
        String mode;
        int typeByte;
        boolean compressed;
        int payloadLen;
        byte[] payload;
    }

    private static String requestKey(CursorTraceState st) {
        String method = st.requestMethod == null ? "" : st.requestMethod + " ";
        String uri = st.requestUri == null ? "" : st.requestUri;
        return method + uri;
    }

    private static String headersToString(HttpHeaders headers) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> h : headers) {
            sb.append(h.getKey()).append(": ").append(h.getValue()).append('\n');
        }
        if (sb.length() == 0) {
            return "(none)";
        }
        return sb.toString();
    }

    private static String fullUtf8(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "(empty)";
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String safeChannelId(Channel channel) {
        if (channel == null || channel.id() == null) {
            return null;
        }
        return channel.id().asShortText();
    }

    private static String headerFirstIgnoreCase(HttpHeaders headers, String name) {
        if (headers == null || name == null) {
            return null;
        }
        String exact = headers.get(name);
        if (exact != null) {
            return exact;
        }
        for (String n : headers.names()) {
            if (n != null && n.equalsIgnoreCase(name)) {
                return headers.get(n);
            }
        }
        return null;
    }

    private static int seenCount(ConcurrentHashMap<String, AtomicInteger> map, String key) {
        if (key == null || key.trim().isEmpty()) {
            return 0;
        }
        return map.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
    }

    private static int nextRequestSeq(Channel clientChannel) {
        AtomicInteger seq = clientChannel.attr(REQUEST_SEQ_KEY).get();
        if (seq == null) {
            seq = new AtomicInteger();
            clientChannel.attr(REQUEST_SEQ_KEY).set(seq);
        }
        return seq.incrementAndGet();
    }

    private static boolean isObservedUri(String uri) {
        if (uri == null) {
            return false;
        }
        if (uri.contains("full_stripe_profile" )|| uri.contains("GetEffectiveUserPlugins")) {
            return false;
        }
//        return true;
        return "/agent.v1.AgentService/RunSSE".equals(uri) || "/aiserver.v1.BidiService/BidiAppend".equals(uri);
    }

    private static String classifyUri(String uri) {
        if ("/agent.v1.AgentService/RunSSE".equals(uri)) {
            return "RunSSE";
        }
        if ("/aiserver.v1.BidiService/BidiAppend".equals(uri)) {
            return "BidiAppend";
        }
        return "Other";
    }

    private static String normalizePathOnly(String uri) {
        if (uri == null) {
            return null;
        }
        int q = uri.indexOf('?');
        return q >= 0 ? uri.substring(0, q) : uri;
    }

    private static String valueOrDash(String s) {
        return (s == null || s.isEmpty()) ? "-" : s;
    }

    private static final class PlainLogFormatter extends Formatter {
        @Override
        public String format(LogRecord record) {
            return String.format("%1$tF %1$tT [%2$s] %3$s%n",
                    record.getMillis(),
                    record.getLevel().getName(),
                    formatMessage(record));
        }
    }

    static final class CursorTraceState {
        String requestMethod;
        String requestUri;
        String normalizedUri;
        String uriClass;
        String requestId;
        String sessionId;
        boolean keepAlive;
        String clientChannelId;
        String proxyChannelId;
        int requestSeqOnChannel;
        int requestChunkIndex;
        final ByteArrayOutputStream requestBodyBuffer = new ByteArrayOutputStream(4096);
        final ByteArrayOutputStream responseBodyBuffer = new ByteArrayOutputStream(4096);
        boolean decompressorAdded;
        HttpResponse httpResponse;
        int responseChunkIndex;
    }
}
