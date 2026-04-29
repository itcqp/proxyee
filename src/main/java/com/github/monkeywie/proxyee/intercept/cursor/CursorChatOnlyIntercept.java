package com.github.monkeywie.proxyee.intercept.cursor;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.github.monkeywie.proxyee.OpenAiCursorChatCompatUtil;
import com.github.monkeywie.proxyee.connect.AgentRunSseModelResolver;
import com.github.monkeywie.proxyee.connect.ClientResponseGate;
import com.github.monkeywie.proxyee.connect.CursorConnectUpstreamCodec;
import com.github.monkeywie.proxyee.connect.OpenAiSseDeltaParser;
import com.github.monkeywie.proxyee.connect.RunSseToUnifiedChatBodyConverter;
import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpContentDecompressor;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.AttributeKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.FileWriter;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * 只代理 Cursor 聊天（RunSSE）的拦截器：
 * - 模式1：转发 Cursor 上游，但可修改请求头
 * - 模式2：不请求 Cursor 上游，走 OpenAI 协议（暂用 OpenAiCursorChatCompatUtil），并将 SSE delta 桥接成 RunSSE/Connect 下行
 */
public class CursorChatOnlyIntercept extends HttpProxyIntercept {

    private static final Logger LOG = Logger.getLogger(CursorChatOnlyIntercept.class.getName());
    private static final String DEBUG_LOG_PATH = "debug-caf0ee.log";
    private static final String DEBUG_SESSION_ID = "caf0ee";

    private static final int MAX_FULL_REQUEST_BYTES = 16 * 1024 * 1024;

    private static final String AGGREGATOR_NAME = "cursorChatOnlyAggregator";

    // RunSSE 首包可能仅携带 "$<uuid>" 作为 requestId；用户文本在 BidiAppend 里
    private static final Pattern DOLLAR_UUID_ONLY =
            Pattern.compile("^\\$[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final ConcurrentHashMap<String, String> REQUEST_PROMPT_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, PendingRun> PENDING_RUNS = new ConcurrentHashMap<>();
    private static final Pattern RICHTEXT_TEXT_PATTERN =
            Pattern.compile("\\\"text\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\\\\\"])*)\\\"");
    private static final Pattern PLAINTEXT_TEXT_PATTERN =
            Pattern.compile("\"text\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern MODEL_SAFE =
            Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._:\\-]{0,63}$");

    private final CursorChatMode mode;
    private final Consumer<io.netty.handler.codec.http.HttpHeaders> headerModifier;

    private static final ExecutorService STREAM_POOL = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "cursor-chat-only-stream");
        t.setDaemon(true);
        return t;
    });

    private static final AttributeKey<ByteArrayOutputStream> ATTR_UPSTREAM_CONNECT_BUF =
            AttributeKey.valueOf("cursor.chat.upstreamConnectBuf");

    public CursorChatOnlyIntercept(CursorChatMode mode,
                                  Consumer<io.netty.handler.codec.http.HttpHeaders> headerModifier) {
        this.mode = mode == null ? CursorChatMode.CURSOR_FORWARD : mode;
        this.headerModifier = headerModifier;
    }

    @Override
    public void beforeRequest(Channel clientChannel, HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline)
            throws Exception {
        // #region agent log
        dbg("pre", "H0", "beforeRequest(HttpRequest)", "enter",
                "{\"cls\":\"" + (httpRequest == null ? "null" : httpRequest.getClass().getName()) + "\""
                        + ",\"uri\":\"" + esc(httpRequest == null ? null : httpRequest.uri()) + "\""
                        + ",\"method\":\"" + esc(httpRequest == null ? null : httpRequest.method().name()) + "\""
                        + ",\"mode\":\"" + String.valueOf(mode) + "\""
                        + ",\"isFull\":" + (httpRequest instanceof io.netty.handler.codec.http.FullHttpRequest)
                        + "}");
        // #endregion
        if (!matchChatRelated(httpRequest, pipeline)) {
            pipeline.beforeRequest(clientChannel, httpRequest);
            return;
        }

        if (httpRequest instanceof io.netty.handler.codec.http.FullHttpRequest) {
            handleFullRequest(clientChannel, (io.netty.handler.codec.http.FullHttpRequest) httpRequest, pipeline);
            return;
        }

        // 需要聚合成 FullHttpRequest 才能解析 RunSSE body
        pipeline.resetBeforeHead();
        if (clientChannel.pipeline().get("cursorChatOnlyDecompress") == null) {
            clientChannel.pipeline().addAfter("httpCodec", "cursorChatOnlyDecompress", new HttpContentDecompressor());
        }
        if (clientChannel.pipeline().get(AGGREGATOR_NAME) == null) {
            clientChannel.pipeline().addAfter("cursorChatOnlyDecompress", AGGREGATOR_NAME,
                    new HttpObjectAggregator(MAX_FULL_REQUEST_BYTES));
        }
        // #region agent log
        dbg("pre", "H4", "beforeRequest(HttpRequest)", "aggregator_added_fireChannelRead", "{}");
        // #endregion
        clientChannel.pipeline().fireChannelRead(httpRequest);
    }

    @Override
    public void beforeRequest(Channel clientChannel, io.netty.handler.codec.http.HttpContent httpContent,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        pipeline.beforeRequest(clientChannel, httpContent);
    }

    @Override
    public void afterResponse(Channel clientChannel, Channel proxyChannel, io.netty.handler.codec.http.HttpResponse httpResponse,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        // 清理聚合器，避免影响后续请求
        if (clientChannel.pipeline().get(AGGREGATOR_NAME) != null) {
            clientChannel.pipeline().remove(AGGREGATOR_NAME);
        }
        if (clientChannel.pipeline().get("cursorChatOnlyDecompress") != null) {
            clientChannel.pipeline().remove("cursorChatOnlyDecompress");
        }
        pipeline.afterResponse(clientChannel, proxyChannel, httpResponse);
    }

    @Override
    public void afterResponse(Channel clientChannel, Channel proxyChannel, io.netty.handler.codec.http.HttpContent httpContent,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        try {
            // 仅在 CURSOR_FORWARD 时抓 Cursor 真正下行帧（用于反推 tool_call/tool_result 格式）
            if (mode == CursorChatMode.CURSOR_FORWARD && pipeline != null && pipeline.getHttpRequest() != null) {
                String path = normalizePath(pipeline.getHttpRequest().uri());
                if (path.contains("RunSSE")) {
                    ByteArrayOutputStream buf = proxyChannel.attr(ATTR_UPSTREAM_CONNECT_BUF).get();
                    if (buf == null) {
                        buf = new ByteArrayOutputStream(16 * 1024);
                        proxyChannel.attr(ATTR_UPSTREAM_CONNECT_BUF).set(buf);
                    }
                    byte[] chunk = extractBytes(httpContent);
                    if (chunk != null && chunk.length > 0) {
                        buf.write(chunk);
                        parseAndLogConnectFrames(buf, "pre");
                    }
                    if (httpContent instanceof LastHttpContent) {
                        // flush remaining (may be incomplete)
                        parseAndLogConnectFrames(buf, "pre");
                        proxyChannel.attr(ATTR_UPSTREAM_CONNECT_BUF).set(null);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
    }

    private boolean match(HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline) {
        if (httpRequest == null) {
            return false;
        }
        if (!HttpMethod.POST.equals(httpRequest.method())) {
            return false;
        }
        String hostFallback = pipeline.getRequestProto() == null ? null : pipeline.getRequestProto().getHost();
        String host = extractHost(httpRequest.headers(), hostFallback);
        if (!isCursorApiHost(host)) {
            return false;
        }
        String path = normalizePath(httpRequest.uri());
        return path.contains("RunSSE");
    }

    private boolean matchChatRelated(HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline) {
        if (httpRequest == null) {
            return false;
        }
        if (!HttpMethod.POST.equals(httpRequest.method())) {
            return false;
        }
        String hostFallback = pipeline.getRequestProto() == null ? null : pipeline.getRequestProto().getHost();
        String host = extractHost(httpRequest.headers(), hostFallback);
        if (!isCursorApiHost(host)) {
            return false;
        }
        String path = normalizePath(httpRequest.uri());
        return path.contains("RunSSE") || path.contains("BidiAppend");
    }

    private void handleFullRequest(Channel clientChannel,
                                   io.netty.handler.codec.http.FullHttpRequest fullReq,
                                   HttpProxyInterceptPipeline pipeline) throws Exception {
        try {
            // #region agent log
            int msgRef = fullReq == null ? -1 : fullReq.refCnt();
            int contentRef = (fullReq == null || fullReq.content() == null) ? -1 : fullReq.content().refCnt();
            dbg("pre", "H1", "handleFullRequest", "enter",
                    "{\"msgRefCnt\":" + msgRef + ",\"contentRefCnt\":" + contentRef
                            + ",\"uri\":\"" + esc(fullReq == null ? null : fullReq.uri()) + "\""
                            + ",\"mode\":\"" + String.valueOf(mode) + "\""
                            + "}");
            // #endregion
            if (headerModifier != null && mode == CursorChatMode.CURSOR_FORWARD) {
                headerModifier.accept(fullReq.headers());
            }

            String path = normalizePath(fullReq.uri());
            if (path.contains("BidiAppend")) {
                // 尝试从 BidiAppend 缓存本轮用户 prompt（供 RunSSE 首包仅 requestId 的情况使用）
                byte[] body = extractBody(fullReq);
                cachePromptFromBidiAppend(fullReq.headers(), body);
                // 仍然透传给 Cursor
            }

            // OpenAI 兼容模式：只接管 RunSSE。BidiAppend/其他 RPC 必须透传，否则会产生额外上游请求与状态异常。
            if (mode == CursorChatMode.OPENAI_COMPAT && path.contains("RunSSE")) {
                boolean keepAlive = HttpUtil.isKeepAlive(fullReq);
                byte[] body = extractBody(fullReq);
                io.netty.handler.codec.http.HttpHeaders headersSnapshot = fullReq.headers().copy();
                String uriSnapshot = fullReq.uri();
                streamLocalOpenAiCompatAsRunSse(clientChannel, headersSnapshot, uriSnapshot, body, keepAlive);
                // #region agent log
                dbg("pre", "H1", "handleFullRequest", "openai_compat_return_before_release",
                        "{\"willRelease\":false,\"msgRefCntBefore\":" + fullReq.refCnt()
                                + ",\"contentRefCntBefore\":" + (fullReq.content() == null ? -1 : fullReq.content().refCnt())
                                + "}");
                // #endregion
                return;
            }

            // 默认：透传给 Cursor，上游连接由 proxyee 处理
            fullReq.content().markReaderIndex();
            fullReq.content().retain();
            if (fullReq.headers().contains(HttpHeaderNames.CONTENT_LENGTH)) {
                fullReq.headers().set(HttpHeaderNames.CONTENT_LENGTH, fullReq.content().readableBytes());
            }
            // FullHttpRequest 同时是 HttpRequest + HttpContent；这里显式走 HttpRequest 分支避免重载歧义
            // #region agent log
            dbg("pre", "H2", "handleFullRequest", "cursor_forward_before_pipeline",
                    "{\"msgRefCnt\":" + fullReq.refCnt()
                            + ",\"contentRefCnt\":" + (fullReq.content() == null ? -1 : fullReq.content().refCnt())
                            + "}");
            // #endregion
            pipeline.beforeRequest(clientChannel, (HttpRequest) fullReq);
        } finally {
            // 让请求体可被 proxyee 继续读取
            if (fullReq.content() != null) {
                try {
                    fullReq.content().resetReaderIndex();
                } catch (Exception ignored) {
                }
            }
        }
    }

    // #region agent log
    private static void dbg(String runId, String hypothesisId, String loc, String msg, String dataJson) {
        try (FileWriter fw = new FileWriter(DEBUG_LOG_PATH, true)) {
            fw.write("{\"sessionId\":\"" + DEBUG_SESSION_ID
                    + "\",\"runId\":\"" + esc(runId)
                    + "\",\"hypothesisId\":\"" + esc(hypothesisId)
                    + "\",\"location\":\"" + esc(loc)
                    + "\",\"message\":\"" + esc(msg)
                    + "\",\"data\":" + (dataJson == null ? "null" : dataJson)
                    + ",\"timestamp\":" + System.currentTimeMillis() + "}\n");
        } catch (Exception ignored) {
        }
    }

    private static String esc(String s) {
        if (s == null) {
            return "null";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
    // #endregion

    private void streamLocalOpenAiCompatAsRunSse(Channel clientChannel,
                                                 io.netty.handler.codec.http.HttpHeaders requestHeaders,
                                                 String requestUri,
                                                 byte[] rawRunSseBody,
                                                 boolean keepAlive) {
        ClientResponseGate gate = ClientResponseGate.forChannel(clientChannel);
        gate.enterOrEnqueue(() -> {
            DefaultHttpResponse head = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
            head.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/connect+proto");
            head.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
            HttpUtil.setKeepAlive(head, keepAlive);
            clientChannel.writeAndFlush(head);

            STREAM_POOL.execute(() -> {
                boolean pendingRegistered = false;
                try {
                    String token = CursorConnectUpstreamCodec.parseBearerToken(requestHeaders);
                    if (StrUtil.isBlank(token)) {
                        writeConnectFrame(clientChannel, buildAgentTextDeltaFrame("Missing Authorization Bearer token"));
                        writeConnectFrame(clientChannel, buildAgentTurnEndedFrame());
                        writeConnectFrame(clientChannel, buildConnectSuccessEndStreamFrame());
                        finishChunkedResponse(clientChannel, keepAlive);
                        return;
                    }

                    AgentRunSseModelResolver.ModelResolution mr =
                            AgentRunSseModelResolver.resolveDetail(requestHeaders, normalizePath(requestUri), rawRunSseBody);
                    String model = sanitizeModel(mr == null ? null : mr.model);

                    // #region agent log
                    // RunSSE 请求体里通常带 rules/skills/tools 元信息；这里仅做统计，不记录具体内容
                    try {
                        byte[] payload = rawRunSseBody;
                        if (payload != null && payload.length >= 5) {
                            int len = ((payload[1] & 0xFF) << 24)
                                    | ((payload[2] & 0xFF) << 16)
                                    | ((payload[3] & 0xFF) << 8)
                                    | (payload[4] & 0xFF);
                            if (len > 0 && len <= 4 * 1024 * 1024 && 5 + len <= payload.length) {
                                byte[] inner = new byte[len];
                                System.arraycopy(payload, 5, inner, 0, len);
                                boolean compressed = (payload[0] & 1) != 0;
                                byte[] d = compressed ? com.github.monkeywie.proxyee.connect.ConnectProtoUtil.gzipDecompress(inner) : inner;
                                if (d != null) {
                                    payload = d;
                                }
                            }
                        }
                        String view = payload == null ? "" : new String(payload, StandardCharsets.UTF_8);
                        String lower = view.toLowerCase(Locale.ROOT);
                        int toolHits = countSubstr(lower, "tool");
                        int skillsHits = countSubstr(lower, "skill");
                        int rulesHits = countSubstr(lower, "rule");
                        int functionHits = countSubstr(lower, "function");
                        dbg("pre", "H_RUNSSE_BODY", "streamLocalOpenAiCompatAsRunSse", "runsse_body_stats",
                                "{\"bodyLen\":" + (rawRunSseBody == null ? 0 : rawRunSseBody.length)
                                        + ",\"payloadUtf8Len\":" + lower.length()
                                        + ",\"toolHits\":" + toolHits
                                        + ",\"skillsHits\":" + skillsHits
                                        + ",\"rulesHits\":" + rulesHits
                                        + ",\"functionHits\":" + functionHits
                                        + "}");
                    } catch (Exception ignored) {
                    }
                    // #endregion

                    String guessed = RunSseToUnifiedChatBodyConverter.extractPromptGuess(rawRunSseBody);
                    String requestId = extractDollarUuidRequestId(guessed);
                    String key = requestId == null ? null : normalizeRequestIdKey(requestId);
                    String prompt = resolvePromptForRunSse(guessed, requestId);

                    // #region agent log
                    dbg("pre", "H_PROMPT", "streamLocalOpenAiCompatAsRunSse", "prompt_resolution",
                            "{\"guessed\":\"" + esc(trimForLog(guessed)) + "\""
                                    + ",\"requestId\":\"" + esc(requestId) + "\""
                                    + ",\"cacheHit\":" + (key != null && REQUEST_PROMPT_CACHE.containsKey(key))
                                    + ",\"prompt\":\"" + esc(trimForLog(prompt)) + "\""
                                    + "}");
                    // #endregion

                    // RunSSE 首包常只有 $uuid（requestId）；先挂起，等 BidiAppend 把真实 prompt 缓存后再开始
                    if (key != null && (prompt == null || prompt.trim().isEmpty() || extractDollarUuidRequestId(prompt) != null)) {
                        PendingRun pr = new PendingRun(clientChannel, keepAlive, gate, token, model, key);
                        PENDING_RUNS.put(key, pr);
                        pendingRegistered = true;
                        // #region agent log
                        dbg("pre", "H_PENDING", "streamLocalOpenAiCompatAsRunSse", "pending_registered",
                                "{\"key\":\"" + esc(key) + "\"}");
                        // #endregion
                        return;
                    }

                    String promptUsed = sanitizePrompt(prompt);
                    // #region agent log
                    dbg("pre", "H_REQ", "streamLocalOpenAiCompatAsRunSse", "openai_request_build",
                            "{\"model\":\"" + esc(model) + "\""
                                    + ",\"promptLen\":" + (promptUsed == null ? 0 : promptUsed.length())
                                    + ",\"promptPreview\":\"" + esc(trimForLog(promptUsed)) + "\"}");
                    // #endregion

                    String openAiJson = buildOpenAiChatCompletionsStreamJson(
                            model,
                            promptUsed);

                    OpenAiCursorChatCompatUtil.chatCompletionsStream(token, openAiJson, sseChunk -> {
                        String delta = OpenAiSseDeltaParser.extractDeltaText(sseChunk);
                        if (delta == null || delta.isEmpty()) {
                            return;
                        }
                        writeConnectFrame(clientChannel, buildAgentTextDeltaFrame(delta));
                    });

                    writeConnectFrame(clientChannel, buildAgentTurnEndedFrame());
                    writeConnectFrame(clientChannel, buildConnectSuccessEndStreamFrame());
                    finishChunkedResponse(clientChannel, keepAlive);
                } catch (Exception e) {
                    LOG.log(Level.WARNING, "[CursorChatOnly] local openai compat stream failed", e);
                    try {
                        writeConnectFrame(clientChannel, buildAgentTextDeltaFrame("upstream error: " + e.getMessage()));
                        writeConnectFrame(clientChannel, buildAgentTurnEndedFrame());
                        writeConnectFrame(clientChannel, buildConnectSuccessEndStreamFrame());
                        finishChunkedResponse(clientChannel, keepAlive);
                    } catch (Exception ignored) {
                    }
                } finally {
                    if (!pendingRegistered) {
                        gate.completeCurrentResponse();
                    }
                }
            });
        });
    }

    private static int countSubstr(String s, String needle) {
        if (s == null || needle == null || needle.isEmpty()) {
            return 0;
        }
        int count = 0;
        int idx = 0;
        while (true) {
            int p = s.indexOf(needle, idx);
            if (p < 0) {
                return count;
            }
            count++;
            idx = p + needle.length();
            if (idx >= s.length()) {
                return count;
            }
        }
    }

    private static String hexPrefix(byte[] bytes, int maxBytes) {
        if (bytes == null) {
            return "";
        }
        int n = Math.min(bytes.length, Math.max(0, maxBytes));
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            int b = bytes[i] & 0xFF;
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * 粗略枚举 protobuf 顶层 tag（不解析嵌套），用于反推未知 schema。
     * 输出形如 "1:2,8:2,49:2"（field:wireType）。
     */
    private static String summarizeTopLevelProtobufTags(byte[] data, int maxFields) {
        if (data == null || data.length == 0 || maxFields <= 0) {
            return "";
        }
        int pos = 0;
        int fields = 0;
        StringBuilder sb = new StringBuilder();
        while (pos < data.length && fields < maxFields) {
            int[] tag = readVarintBounded(data, pos, data.length);
            if (tag == null) {
                break;
            }
            int t = tag[0];
            int fieldNumber = t >>> 3;
            int wireType = t & 0x07;
            pos = tag[1];
            if (fieldNumber == 0) {
                break;
            }
            if (sb.length() > 0) {
                sb.append(",");
            }
            sb.append(fieldNumber).append(":").append(wireType);
            fields++;
            switch (wireType) {
                case 0: { // varint
                    int[] vv = readVarintBounded(data, pos, data.length);
                    if (vv == null) {
                        return sb.toString();
                    }
                    pos = vv[1];
                    break;
                }
                case 1: // fixed64
                    pos += 8;
                    break;
                case 2: { // length-delimited
                    int[] len = readVarintBounded(data, pos, data.length);
                    if (len == null) {
                        return sb.toString();
                    }
                    int l = len[0];
                    pos = len[1] + Math.max(0, l);
                    break;
                }
                case 5: // fixed32
                    pos += 4;
                    break;
                default:
                    return sb.toString();
            }
            if (pos < 0 || pos > data.length) {
                break;
            }
        }
        return sb.toString();
    }

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

    private static byte[] extractLengthDelimitedField(byte[] data, int targetFieldNumber, int maxLen) {
        if (data == null || data.length == 0) {
            return null;
        }
        if (maxLen <= 0) {
            maxLen = Integer.MAX_VALUE;
        }
        int pos = 0;
        while (pos < data.length) {
            int[] tag = readVarintBounded(data, pos, data.length);
            if (tag == null) {
                return null;
            }
            int t = tag[0];
            int fieldNumber = t >>> 3;
            int wireType = t & 0x07;
            pos = tag[1];
            if (fieldNumber == 0) {
                return null;
            }
            if (wireType == 2) {
                int[] len = readVarintBounded(data, pos, data.length);
                if (len == null) {
                    return null;
                }
                int l = len[0];
                pos = len[1];
                if (l < 0 || pos + l > data.length) {
                    return null;
                }
                if (fieldNumber == targetFieldNumber) {
                    int take = Math.min(l, maxLen);
                    byte[] out = new byte[take];
                    System.arraycopy(data, pos, out, 0, take);
                    return out;
                }
                pos += l;
            } else if (wireType == 0) {
                int[] vv = readVarintBounded(data, pos, data.length);
                if (vv == null) {
                    return null;
                }
                pos = vv[1];
            } else if (wireType == 1) {
                pos += 8;
            } else if (wireType == 5) {
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

    private static String listTopLevelLengthDelimitedFieldsMeta(byte[] data, int maxFields, int maxLenEach) {
        if (data == null || data.length == 0) {
            return "";
        }
        if (maxFields <= 0) {
            return "";
        }
        int pos = 0;
        int found = 0;
        StringBuilder sb = new StringBuilder();
        while (pos < data.length && found < maxFields) {
            int[] tag = readVarintBounded(data, pos, data.length);
            if (tag == null) {
                break;
            }
            int t = tag[0];
            int fieldNumber = t >>> 3;
            int wireType = t & 0x07;
            pos = tag[1];
            if (fieldNumber == 0) {
                break;
            }
            if (wireType == 2) {
                int[] len = readVarintBounded(data, pos, data.length);
                if (len == null) {
                    break;
                }
                int l = len[0];
                pos = len[1];
                if (l < 0 || pos + l > data.length) {
                    break;
                }
                int take = Math.min(l, maxLenEach <= 0 ? l : maxLenEach);
                byte[] chunk = new byte[take];
                System.arraycopy(data, pos, chunk, 0, take);

                String chunkTagSummary = summarizeTopLevelProtobufTags(chunk, 8);
                String chunkHexPrefix = hexPrefix(chunk, 48);
                String chunkB64 = java.util.Base64.getEncoder().encodeToString(chunk);
                if (chunkB64.length() > 256) {
                    chunkB64 = chunkB64.substring(0, 256) + "...";
                }

                if (sb.length() > 0) {
                    sb.append("|");
                }
                sb.append("f").append(fieldNumber)
                        .append(":len=").append(l)
                        .append(":take=").append(take)
                        .append(":tags=").append(chunkTagSummary)
                        .append(":hex=").append(chunkHexPrefix)
                        .append(":b64=").append(chunkB64);

                found++;
                pos += l;
            } else if (wireType == 0) {
                int[] vv = readVarintBounded(data, pos, data.length);
                if (vv == null) {
                    break;
                }
                pos = vv[1];
            } else if (wireType == 1) {
                pos += 8;
            } else if (wireType == 5) {
                pos += 4;
            } else {
                break;
            }
            if (pos < 0 || pos > data.length) {
                break;
            }
        }
        return sb.toString();
    }

    private static String buildOpenAiChatCompletionsStreamJson(String model, String prompt) {
        JSONObject req = new JSONObject();
        req.set("model", StrUtil.blankToDefault(model, "default"));
        req.set("stream", true);
        JSONArray msgs = new JSONArray();
        msgs.put(new JSONObject().set("role", "user").set("content", prompt == null ? "" : prompt));
        req.set("messages", msgs);
        return req.toString();
    }

    private static void cachePromptFromBidiAppend(io.netty.handler.codec.http.HttpHeaders headers, byte[] body) {
        try {
            // #region agent log
            dbg("pre", "H_TOOL_REQ", "cachePromptFromBidiAppend", "bidiappend_enter",
                    "{\"hasHeaders\":" + (headers != null)
                            + ",\"bodyLen\":" + (body == null ? 0 : body.length)
                            + ",\"hasXRequestId\":" + (headers != null && headers.get("x-request-id") != null)
                            + "}");
            // #endregion
            String extracted = extractHumanTextFromConnectBody(body);
            if (extracted == null) {
                // #region agent log
                dbg("pre", "H_TOOL_REQ", "cachePromptFromBidiAppend", "bidiappend_no_human_text", "{}");
                // #endregion
                return;
            }
            extracted = extracted.trim();
            if (extracted.isEmpty()) {
                return;
            }
            int candScore = userTextCandidateScore(extracted);
            // #region agent log
            dbg("pre", "H_TOOL_REQ", "cachePromptFromBidiAppend", "bidiappend_human_text_candidate",
                    "{\"preview\":\"" + esc(trimForLog(extracted)) + "\""
                            + ",\"len\":" + extracted.length()
                            + ",\"candScore\":" + candScore
                            + ",\"rulesLike\":" + looksLikeRulesOrSkillDump(extracted)
                            + ",\"containsToolWords\":" + (extracted.toLowerCase(Locale.ROOT).contains("tool")
                            || extracted.toLowerCase(Locale.ROOT).contains("function")
                            || extracted.toLowerCase(Locale.ROOT).contains("arguments"))
                            + "}");
            // #endregion
            if (looksLikeRulesOrSkillDump(extracted)) {
                // #region agent log
                dbg("pre", "H_CACHE", "cachePromptFromBidiAppend", "cache_skip_rules_like",
                        "{\"reason\":\"rules_like\",\"preview\":\"" + esc(trimForLog(extracted)) + "\"}");
                // #endregion
                return;
            }
            // requestId 一般可从 x-request-id 取到；取不到就不缓存（避免污染）
            String rid = headers == null ? null : headers.get("x-request-id");
            if (rid == null || rid.trim().isEmpty()) {
                return;
            }
            String key = normalizeRequestIdKey(rid.trim());
            String prompt = sanitizePrompt(extracted);
            // 过滤明显噪声：过短/得分过低的片段（常来自 BidiAppend 的非用户文本帧）
            if (prompt.length() < 4 || candScore < 20) {
                // #region agent log
                dbg("pre", "H_CACHE", "cachePromptFromBidiAppend", "cache_skip_low_quality",
                        "{\"key\":\"" + esc(key) + "\""
                                + ",\"promptLen\":" + prompt.length()
                                + ",\"candScore\":" + candScore
                                + ",\"preview\":\"" + esc(trimForLog(prompt)) + "\"}");
                // #endregion
                return;
            }

            // 避免被后续低质量片段覆盖：只在得分更高时覆盖
            String prev = REQUEST_PROMPT_CACHE.get(key);
            if (prev != null && !prev.trim().isEmpty()) {
                int prevScore = userTextCandidateScore(prev);
                if (prevScore >= candScore) {
                    // #region agent log
                    dbg("pre", "H_CACHE", "cachePromptFromBidiAppend", "cache_keep_existing",
                            "{\"key\":\"" + esc(key) + "\""
                                    + ",\"prevScore\":" + prevScore
                                    + ",\"candScore\":" + candScore
                                    + ",\"prevPreview\":\"" + esc(trimForLog(prev)) + "\""
                                    + ",\"candPreview\":\"" + esc(trimForLog(prompt)) + "\"}");
                    // #endregion
                    return;
                }
            }
            REQUEST_PROMPT_CACHE.put(key, prompt);
            // #region agent log
            dbg("pre", "H_CACHE", "cachePromptFromBidiAppend", "cache_put",
                    "{\"requestId\":\"" + esc(rid.trim()) + "\",\"key\":\"" + esc(key) + "\",\"prompt\":\"" + esc(trimForLog(prompt)) + "\"}");
            // #endregion

            PendingRun pending = PENDING_RUNS.remove(key);
            if (pending != null) {
                // #region agent log
                dbg("pre", "H_PENDING", "cachePromptFromBidiAppend", "pending_found_start_stream",
                        "{\"key\":\"" + esc(key) + "\",\"prompt\":\"" + esc(trimForLog(prompt)) + "\"}");
                // #endregion
                STREAM_POOL.execute(() -> runOpenAiAndBridgeToRunSse(
                        pending.clientChannel,
                        pending.keepAlive,
                        pending.gate,
                        pending.cursorToken,
                        pending.model,
                        prompt));
            }
        } catch (Exception ignored) {
        }
    }

    private static void runOpenAiAndBridgeToRunSse(Channel clientChannel,
                                                   boolean keepAlive,
                                                   ClientResponseGate gate,
                                                   String cursorToken,
                                                   String model,
                                                   String prompt) {
        try {
            String openAiJson = buildOpenAiChatCompletionsStreamJson(model, prompt);
            OpenAiCursorChatCompatUtil.chatCompletionsStream(cursorToken, openAiJson, sseChunk -> {
                String delta = OpenAiSseDeltaParser.extractDeltaText(sseChunk);
                if (delta == null || delta.isEmpty()) {
                    return;
                }
                writeConnectFrame(clientChannel, buildAgentTextDeltaFrame(delta));
            });
            writeConnectFrame(clientChannel, buildAgentTurnEndedFrame());
            writeConnectFrame(clientChannel, buildConnectSuccessEndStreamFrame());
            finishChunkedResponse(clientChannel, keepAlive);
        } catch (Exception e) {
            try {
                writeConnectFrame(clientChannel, buildAgentTextDeltaFrame("upstream error: " + e.getMessage()));
                writeConnectFrame(clientChannel, buildAgentTurnEndedFrame());
                writeConnectFrame(clientChannel, buildConnectSuccessEndStreamFrame());
                finishChunkedResponse(clientChannel, keepAlive);
            } catch (Exception ignored) {
            }
        } finally {
            gate.completeCurrentResponse();
        }
    }

    private static String resolvePromptForRunSse(String guessed, String requestId) {
        String g = guessed == null ? "" : guessed.trim();
        if (!g.isEmpty() && extractDollarUuidRequestId(g) == null) {
            return g;
        }
        if (requestId != null) {
            String cached = REQUEST_PROMPT_CACHE.get(normalizeRequestIdKey(requestId));
            if (cached != null && !cached.trim().isEmpty()) {
                return cached.trim();
            }
        }
        return g.isEmpty() ? "" : g;
    }

    private static String normalizeRequestIdKey(String requestIdOrDollarUuid) {
        if (requestIdOrDollarUuid == null) {
            return null;
        }
        String s = requestIdOrDollarUuid.trim();
        if (s.startsWith("$")) {
            s = s.substring(1);
        }
        return s;
    }

    private static String extractDollarUuidRequestId(String guessed) {
        if (guessed == null) {
            return null;
        }
        String g = guessed.trim();
        if (DOLLAR_UUID_ONLY.matcher(g).matches()) {
            return g;
        }
        return null;
    }

    /**
     * 从 Connect framing body 中提取最像“用户自然语言”的 UTF-8 片段（用于 BidiAppend caching）。
     * 不依赖具体 protobuf schema，避免把二进制当作 prompt。
     */
    private static String extractHumanTextFromConnectBody(byte[] fullBody) {
        if (fullBody == null || fullBody.length == 0) {
            return null;
        }
        byte[] payload = fullBody;
        if (fullBody.length >= 5) {
            int len = ((fullBody[1] & 0xFF) << 24)
                    | ((fullBody[2] & 0xFF) << 16)
                    | ((fullBody[3] & 0xFF) << 8)
                    | (fullBody[4] & 0xFF);
            if (len > 0 && len <= 4 * 1024 * 1024 && 5 + len <= fullBody.length) {
                payload = new byte[len];
                System.arraycopy(fullBody, 5, payload, 0, len);
                boolean compressed = (fullBody[0] & 1) != 0;
                if (compressed) {
                    byte[] d = com.github.monkeywie.proxyee.connect.ConnectProtoUtil.gzipDecompress(payload);
                    if (d != null) {
                        payload = d;
                    }
                }
            }
        }
        // 1) 尝试直接在 payload UTF-8 视图里找 richtext.text
        String rich = extractRichTextTextField(payload);
        if (rich != null && !rich.trim().isEmpty()) {
            String decoded = decodeHexUtf8FromAsciiN(rich, 2);
            return decoded != null ? decoded : rich.trim();
        }
        // 2) payload 往往是二进制，但会“夹带 hex 编码的 JSON/richtext”，先解 hex 再找 "text":"..."
        String fromHexWrapped = extractTextFromHexWrappedJson(payload);
        if (fromHexWrapped != null && !fromHexWrapped.trim().isEmpty()) {
            return fromHexWrapped.trim();
        }
        String bestUtf8 = longestUtf8LikelyText(payload);
        if (bestUtf8 == null) {
            return null;
        }
        String decoded = decodeHexUtf8FromAsciiN(bestUtf8, 2);
        return decoded != null ? decoded : bestUtf8;
    }

    /**
     * 在 payload 的 UTF-8 视图中扫描长 hex 串，解码为 bytes，再从中提取 {"text":"..."} 的值。
     * 适配 Cursor 把 richtext JSON 以 hex 形式夹在二进制 protobuf 里的情况。
     */
    private static String extractTextFromHexWrappedJson(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }
        String view;
        try {
            view = new String(payload, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
        String best = null;
        int bestScore = 0;
        int n = view.length();
        int i = 0;
        while (i < n) {
            char c = view.charAt(i);
            if (!isHexChar(c)) {
                i++;
                continue;
            }
            int j = i;
            while (j < n && isHexChar(view.charAt(j))) {
                j++;
            }
            int len = j - i;
            if (len >= 64 && (len % 2 == 0)) {
                String hex = view.substring(i, j);
                byte[] bytes = tryDecodeHexToBytes(hex);
                if (bytes != null && bytes.length > 0) {
                    String cand = extractTextFromDecodedBytes(bytes);
                    if (cand != null && !cand.trim().isEmpty()) {
                        int sc = userTextCandidateScore(cand);
                        if (sc > bestScore) {
                            best = cand.trim();
                            bestScore = sc;
                        }
                    }
                }
            }
            i = j + 1;
        }
        // #region agent log
        dbg("pre", "H_TEXTCAND", "extractTextFromHexWrappedJson", "best_hexwrapped",
                "{\"score\":" + bestScore + ",\"best\":\"" + esc(trimForLog(best)) + "\"}");
        // #endregion
        return bestScore > 0 ? best : null;
    }

    private static byte[] tryDecodeHexToBytes(String hex) {
        try {
            int len = hex.length();
            byte[] bytes = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                int hi = Character.digit(hex.charAt(i), 16);
                int lo = Character.digit(hex.charAt(i + 1), 16);
                if (hi < 0 || lo < 0) {
                    return null;
                }
                bytes[i / 2] = (byte) ((hi << 4) | lo);
            }
            return bytes;
        } catch (Exception e) {
            return null;
        }
    }

    private static String extractTextFromDecodedBytes(byte[] bytes) {
        String s;
        try {
            s = new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
        Matcher m = PLAINTEXT_TEXT_PATTERN.matcher(s);
        String best = null;
        int bestScore = 0;
        while (m.find()) {
            String t = m.group(1);
            if (t == null) continue;
            t = t.trim();
            if (t.isEmpty()) continue;
            // 若 text 本身是 hex utf8（e4bda0...），解码
            String hd = decodeHexUtf8FromAsciiN(t, 2);
            if (hd != null && !hd.trim().isEmpty()) {
                t = hd.trim();
            }
            if (looksLikeRulesOrSkillDump(t)) {
                continue;
            }
            int sc = userTextCandidateScore(t);
            if (sc > bestScore) {
                best = t;
                bestScore = sc;
            }
        }
        return bestScore > 0 ? best : null;
    }

    private static boolean looksLikeRulesOrSkillDump(String s) {
        if (s == null) return false;
        String lower = s.toLowerCase(Locale.ROOT);
        if (lower.contains("name: \"imagegen\"") || lower.contains("description:") || lower.contains("## top-level")) {
            return true;
        }
        if (lower.contains("shared prompt guidance") || lower.contains("built-in tool mode") || lower.contains("fallback cli mode")) {
            return true;
        }
        // 明显是 frontmatter/markdown
        if (lower.contains("---") && lower.contains("name:") && lower.length() > 200) {
            return true;
        }
        return false;
    }

    private static String decodeHexUtf8FromAsciiN(String s, int rounds) {
        String cur = s;
        for (int i = 0; i < rounds; i++) {
            String next = decodeHexUtf8FromAscii(cur);
            if (next == null || next.trim().isEmpty()) {
                return i == 0 ? null : cur;
            }
            if (next.equals(cur)) {
                break;
            }
            cur = next;
        }
        return cur;
    }

    /**
     * Cursor 的某些请求体会把 UTF-8 字节以十六进制 ASCII 形式内嵌在可读串里（如 e4bda0...）。
     * 这里扫描长 hex 串并尝试解码成 UTF-8 文本，优先返回包含 CJK 的候选。
     */
    private static String decodeHexUtf8FromAscii(String s) {
        if (s == null) {
            return null;
        }
        String src = s.trim();
        if (src.isEmpty()) {
            return null;
        }
        String best = null;
        int bestScore = 0;
        int n = src.length();
        int i = 0;
        while (i < n) {
            char c = src.charAt(i);
            if (!isHexChar(c)) {
                i++;
                continue;
            }
            int j = i;
            while (j < n && isHexChar(src.charAt(j))) {
                j++;
            }
            int len = j - i;
            if (len >= 12 && (len % 2 == 0)) {
                String hex = src.substring(i, j);
                String decoded = tryDecodeHexToUtf8BestTextSegment(hex);
                if (decoded != null) {
                    int score = textScore(decoded);
                    if (score > bestScore) {
                        best = decoded;
                        bestScore = score;
                    }
                }
            }
            i = j + 1;
        }
        return bestScore > 0 ? best : null;
    }

    private static boolean isHexChar(char c) {
        return (c >= '0' && c <= '9')
                || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
    }

    private static String tryDecodeHexToUtf8BestTextSegment(String hex) {
        try {
            int len = hex.length();
            byte[] bytes = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                int hi = Character.digit(hex.charAt(i), 16);
                int lo = Character.digit(hex.charAt(i + 1), 16);
                if (hi < 0 || lo < 0) {
                    return null;
                }
                bytes[i / 2] = (byte) ((hi << 4) | lo);
            }
            // 允许替换字符出现：二进制里混入了 UTF-8 文本时，直接整体 decode 会有 \uFFFD。
            // 我们只从中提取“最长可读文本片段”。
            String decoded = new String(bytes, StandardCharsets.UTF_8);
            String best = longestUtf8LikelyText(decoded.getBytes(StandardCharsets.UTF_8));
            if (best != null && !best.trim().isEmpty()) {
                return best.trim();
            }
            // fallback：按 \uFFFD 拆段挑最好的一段
            String[] parts = decoded.split("\uFFFD+");
            String best2 = null;
            int bestScore = 0;
            for (String p : parts) {
                if (p == null) continue;
                String t = p.trim();
                if (t.isEmpty()) continue;
                int sc = textScore(t);
                if (sc > bestScore) {
                    best2 = t;
                    bestScore = sc;
                }
            }
            return bestScore > 0 ? best2 : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 评分：包含更多 CJK/字母数字/标点者更高。
     */
    private static int textScore(String s) {
        if (s == null || s.isEmpty()) {
            return 0;
        }
        int score = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            Character.UnicodeBlock b = Character.UnicodeBlock.of(c);
            if (b == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
                    || b == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A) {
                score += 6;
            } else if (Character.isLetterOrDigit(c)) {
                score += 2;
            } else if (!Character.isISOControl(c)) {
                score += 1;
            }
        }
        // 太短的不要
        if (s.length() < 2) {
            return 0;
        }
        return score;
    }

    private static String extractRichTextTextField(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }
        String s;
        try {
            s = new String(payload, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
        Matcher m = RICHTEXT_TEXT_PATTERN.matcher(s);
        String best = null;
        int bestScore = Integer.MIN_VALUE;
        String[] topPrev = new String[3];
        int[] topScore = new int[] {Integer.MIN_VALUE, Integer.MIN_VALUE, Integer.MIN_VALUE};
        while (m.find()) {
            String raw = m.group(1);
            if (raw == null) {
                continue;
            }
            String t = unescapeJsonString(raw);
            if (t == null) {
                continue;
            }
            t = t.trim();
            if (t.isEmpty()) {
                continue;
            }
            String hexDecoded = decodeHexUtf8FromAsciiN(t, 2);
            if (hexDecoded != null && !hexDecoded.trim().isEmpty()) {
                t = hexDecoded.trim();
            }
            if (extractDollarUuidRequestId(t) != null) {
                continue;
            }
            int sc = userTextCandidateScore(t);
            if (sc > bestScore) {
                best = t;
                bestScore = sc;
            }
            // track top3 for debugging
            for (int i = 0; i < 3; i++) {
                if (sc > topScore[i]) {
                    for (int k = 2; k > i; k--) {
                        topScore[k] = topScore[k - 1];
                        topPrev[k] = topPrev[k - 1];
                    }
                    topScore[i] = sc;
                    topPrev[i] = trimForLog(t);
                    break;
                }
            }
        }
        // #region agent log
        dbg("pre", "H_TEXTCAND", "extractRichTextTextField", "top_candidates",
                "{\"top0Score\":" + topScore[0] + ",\"top0\":\"" + esc(topPrev[0]) + "\""
                        + ",\"top1Score\":" + topScore[1] + ",\"top1\":\"" + esc(topPrev[1]) + "\""
                        + ",\"top2Score\":" + topScore[2] + ",\"top2\":\"" + esc(topPrev[2]) + "\""
                        + "}");
        // #endregion
        return best;
    }

    private static int userTextCandidateScore(String t) {
        if (t == null) {
            return Integer.MIN_VALUE;
        }
        String s = t.trim();
        if (s.isEmpty()) {
            return Integer.MIN_VALUE;
        }
        // Prefer short-ish user questions; strongly penalize huge rule/skill dumps
        int len = s.length();
        int score = 0;
        int cjk = 0;
        int badLines = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            Character.UnicodeBlock b = Character.UnicodeBlock.of(c);
            if (b == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
                    || b == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A) {
                cjk++;
            }
            if (c == '\n' || c == '\r') {
                badLines++;
            }
        }
        score += cjk * 10;
        // base preference for being concise
        if (len <= 120) {
            score += 50;
        } else if (len <= 500) {
            score += 10;
        } else {
            score -= (len / 10);
        }
        // penalize markdown-ish / frontmatter-ish blocks
        String lower = s.toLowerCase();
        if (lower.contains("##") || lower.contains("---") || lower.contains("name:") || lower.contains("description:")) {
            score -= 200;
        }
        if (lower.contains("skill") && len > 200) {
            score -= 200;
        }
        // penalize too many lines
        if (badLines > 2) {
            score -= badLines * 20;
        }
        // ensure some signal
        score += Math.min(30, textScore(s));
        return score;
    }

    private static String unescapeJsonString(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (i + 1 >= s.length()) {
                break;
            }
            char n = s.charAt(++i);
            switch (n) {
                case '"':
                    out.append('"');
                    break;
                case '\\':
                    out.append('\\');
                    break;
                case '/':
                    out.append('/');
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    if (i + 4 < s.length()) {
                        try {
                            int cp = Integer.parseInt(s.substring(i + 1, i + 5), 16);
                            out.append((char) cp);
                            i += 4;
                        } catch (Exception ignored) {
                        }
                    }
                    break;
                default:
                    out.append(n);
            }
        }
        return out.toString();
    }

    private static final class PendingRun {
        final Channel clientChannel;
        final boolean keepAlive;
        final ClientResponseGate gate;
        final String cursorToken;
        final String model;
        final String key;

        PendingRun(Channel clientChannel,
                   boolean keepAlive,
                   ClientResponseGate gate,
                   String cursorToken,
                   String model,
                   String key) {
            this.clientChannel = clientChannel;
            this.keepAlive = keepAlive;
            this.gate = gate;
            this.cursorToken = cursorToken;
            this.model = model;
            this.key = key;
        }
    }
    private static String longestUtf8LikelyText(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        String s;
        try {
            s = new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
        StringBuilder cur = new StringBuilder();
        String best = "";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (isGoodTextChar(c)) {
                cur.append(c);
            } else {
                if (cur.length() > best.length()) {
                    best = cur.toString();
                }
                cur.setLength(0);
            }
        }
        if (cur.length() > best.length()) {
            best = cur.toString();
        }
        best = best.trim().replaceAll("\r\n|\n|\r", " ");
        if (best.length() > 8000) {
            best = best.substring(0, 8000);
        }
        if (best.isEmpty()) {
            return null;
        }
        // 很短的串可能是 uuid/噪声
        if (best.length() <= 1) {
            return null;
        }
        return best;
    }

    private static boolean isGoodTextChar(char c) {
        if (c == '\uFFFD') {
            return false;
        }
        if (c == '\n' || c == '\r' || c == '\t' || c == ' ') {
            return true;
        }
        if (c < 0x20) {
            return false;
        }
        // CJK Unified Ideographs / punctuation / common printable
        Character.UnicodeBlock b = Character.UnicodeBlock.of(c);
        if (b == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
                || b == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A
                || b == Character.UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION
                || b == Character.UnicodeBlock.GENERAL_PUNCTUATION) {
            return true;
        }
        if (Character.isLetterOrDigit(c)) {
            return true;
        }
        String punct = ".,!?;:'\"()[]{}<>@#$/\\-_=+*&%^|~`";
        return punct.indexOf(c) >= 0;
    }

    private static String sanitizeModel(String raw) {
        if (raw == null) {
            return "default";
        }
        String v = raw.trim();
        if (v.isEmpty()) {
            return "default";
        }
        if (v.length() > 64) {
            return "default";
        }
        if (!MODEL_SAFE.matcher(v).matches()) {
            return "default";
        }
        return v;
    }

    private static String sanitizePrompt(String raw) {
        if (raw == null) {
            return "";
        }
        String s = raw.replace("\r", " ").replace("\n", " ").trim();
        if (s.length() > 8000) {
            s = s.substring(0, 8000);
        }
        if (extractDollarUuidRequestId(s) != null) {
            return "";
        }
        return s;
    }

    private static String trimForLog(String s) {
        if (s == null) {
            return "";
        }
        String t = s.replace("\r", " ").replace("\n", " ").trim();
        if (t.length() > 160) {
            return t.substring(0, 160) + "…";
        }
        return t;
    }

    public static Consumer<io.netty.handler.codec.http.HttpHeaders> headerPatchModifier(String headerPatch) {
        if (headerPatch == null || headerPatch.trim().isEmpty()) {
            return null;
        }
        final String raw = headerPatch.trim();
        return headers -> applyHeaderPatch(headers, raw);
    }

    private static void applyHeaderPatch(io.netty.handler.codec.http.HttpHeaders headers, String raw) {
        if (headers == null || raw == null || raw.trim().isEmpty()) {
            return;
        }
        // 支持两种形态：
        // 1) JSON: {"k":"v","a":"b"}
        // 2) kv: k=v; a=b
        String r = raw.trim();
        if (r.startsWith("{") && r.endsWith("}")) {
            try {
                JSONObject obj = JSONUtil.parseObj(r);
                for (Map.Entry<String, Object> e : obj) {
                    String k = e.getKey();
                    Object v = e.getValue();
                    if (k != null && v != null) {
                        headers.set(k, String.valueOf(v));
                    }
                }
                return;
            } catch (Exception ignored) {
                // fallback to kv
            }
        }
        StringTokenizer st = new StringTokenizer(r, ";");
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            if (token == null) continue;
            String t = token.trim();
            if (t.isEmpty()) continue;
            int eq = t.indexOf('=');
            if (eq <= 0) continue;
            String k = t.substring(0, eq).trim();
            String v = t.substring(eq + 1).trim();
            if (!k.isEmpty()) {
                headers.set(k, v);
            }
        }
    }

    private static byte[] extractBody(io.netty.handler.codec.http.FullHttpRequest req) {
        if (req == null || req.content() == null) {
            return new byte[0];
        }
        ByteBuf buf = req.content();
        int n = buf.readableBytes();
        if (n <= 0) {
            return new byte[0];
        }
        byte[] out = new byte[n];
        buf.getBytes(buf.readerIndex(), out);
        return out;
    }

    private static byte[] extractBytes(io.netty.handler.codec.http.HttpContent content) {
        if (content == null || content.content() == null) {
            return null;
        }
        ByteBuf b = content.content();
        int n = b.readableBytes();
        if (n <= 0) {
            return null;
        }
        byte[] out = new byte[n];
        b.getBytes(b.readerIndex(), out);
        return out;
    }

    private static void parseAndLogConnectFrames(ByteArrayOutputStream buf, String runId) {
        if (buf == null) {
            return;
        }
        byte[] data = buf.toByteArray();
        int pos = 0;
        while (pos + 5 <= data.length) {
            int typeByte = data[pos] & 0xFF;
            int len = ((data[pos + 1] & 0xFF) << 24)
                    | ((data[pos + 2] & 0xFF) << 16)
                    | ((data[pos + 3] & 0xFF) << 8)
                    | (data[pos + 4] & 0xFF);
            if (len < 0 || len > 8 * 1024 * 1024) {
                break;
            }
            if (pos + 5 + len > data.length) {
                break;
            }
            byte[] wire = new byte[5 + len];
            System.arraycopy(data, pos, wire, 0, wire.length);
            pos += wire.length;

            byte[] payload = com.github.monkeywie.proxyee.connect.ConnectProtoUtil.extractPayloadFromWire(wire);
            String agentKind = payload == null ? "null" : com.github.monkeywie.proxyee.connect.ConnectProtoUtil.describeAgentServerMessageKind(payload);
            String unifiedKind = payload == null ? "null" : com.github.monkeywie.proxyee.connect.ConnectProtoUtil.describeUnifiedChatResponseKind(payload);
            String toolSummary = payload == null ? null : com.github.monkeywie.proxyee.connect.ConnectProtoUtil.extractUnifiedChatToolCallSummary(payload);
            // #region agent log
            dbg(runId, "H_DOWNSTREAM", "afterResponse(HttpContent)", "cursor_runsse_frame",
                    "{\"typeByte\":" + typeByte
                            + ",\"len\":" + len
                            + ",\"agentKind\":\"" + esc(agentKind) + "\""
                            + ",\"unifiedKind\":\"" + esc(unifiedKind) + "\""
                            + ",\"toolSummary\":\"" + esc(toolSummary) + "\""
                            + "}");
            // #endregion

            // #region agent log
            // 仅在检测到 tool_call_v2 相关帧时，输出截断的 payload base64 供反推字段（不含鉴权信息）
            if (toolSummary != null && toolSummary.contains("client_side_tool_v2_call") && payload != null) {
                String b64 = java.util.Base64.getEncoder().encodeToString(payload);
                if (b64.length() > 2048) {
                    b64 = b64.substring(0, 2048) + "...";
                }
                String tagSummary = summarizeTopLevelProtobufTags(payload, 32);
                String hexPrefix = hexPrefix(payload, 64);
                byte[] inner1 = extractLengthDelimitedField(payload, 1, 128 * 1024);
                String innerTagSummary = summarizeTopLevelProtobufTags(inner1, 32);
                String innerHexPrefix = hexPrefix(inner1, 96);
                String inner1LdFieldsMeta = inner1 == null ? "" : listTopLevelLengthDelimitedFieldsMeta(inner1, 6, 256);

                // params 子消息：优先抓常见 field 8(read_file) / 23(run_terminal_command) / 54(ripgrep_raw) / 52(list_dir_v2) 等
                int[] paramFields = new int[] {8, 23, 54, 52, 53, 55, 26, 69};
                String paramsMeta = "";
                if (inner1 != null && inner1.length > 0) {
                    StringBuilder pm = new StringBuilder();
                    for (int pf : paramFields) {
                        byte[] pbytes = extractLengthDelimitedField(inner1, pf, 256 * 1024);
                        if (pbytes == null || pbytes.length == 0) {
                            continue;
                        }
                        String pTag = summarizeTopLevelProtobufTags(pbytes, 32);
                        String pHex = hexPrefix(pbytes, 96);
                        String pB64 = java.util.Base64.getEncoder().encodeToString(pbytes);
                        if (pB64.length() > 2048) {
                            pB64 = pB64.substring(0, 2048) + "...";
                        }
                        if (pm.length() > 0) {
                            pm.append("|");
                        }
                        pm.append("f").append(pf)
                                .append(":len=").append(pbytes.length)
                                .append(",tags=").append(pTag)
                                .append(",hex=").append(pHex)
                                .append(",b64=").append(pB64);
                    }
                    paramsMeta = pm.toString();
                }
                dbg(runId, "H_DOWNSTREAM", "afterResponse(HttpContent)", "cursor_runsse_tool_payload_b64",
                        "{\"agentKind\":\"" + esc(agentKind) + "\""
                                + ",\"unifiedKind\":\"" + esc(unifiedKind) + "\""
                                + ",\"toolSummary\":\"" + esc(toolSummary) + "\""
                                + ",\"payloadLen\":" + payload.length
                                + ",\"tagSummary\":\"" + esc(tagSummary) + "\""
                                + ",\"hexPrefix\":\"" + esc(hexPrefix) + "\""
                                + ",\"inner1Len\":" + (inner1 == null ? 0 : inner1.length)
                                + ",\"inner1TagSummary\":\"" + esc(innerTagSummary) + "\""
                                + ",\"inner1HexPrefix\":\"" + esc(innerHexPrefix) + "\""
                                + ",\"inner1LdFieldsMeta\":\"" + esc(inner1LdFieldsMeta) + "\""
                                + ",\"paramsMeta\":\"" + esc(paramsMeta) + "\""
                                + ",\"payloadB64\":\"" + esc(b64) + "\""
                                + "}");
            }
            // #endregion
        }
        if (pos > 0) {
            ByteArrayOutputStream nb = new ByteArrayOutputStream(Math.max(0, data.length - pos) + 16);
            if (pos < data.length) {
                nb.write(data, pos, data.length - pos);
            }
            buf.reset();
            try {
                buf.write(nb.toByteArray());
            } catch (IOException ignored) {
            }
        }
    }

    private static String normalizePath(String uri) {
        if (uri == null || uri.isEmpty()) {
            return "/";
        }
        try {
            java.net.URI parsed = java.net.URI.create(uri);
            if (parsed.getScheme() != null) {
                String path = parsed.getRawPath();
                if (path == null || path.isEmpty()) {
                    path = "/";
                }
                if (parsed.getRawQuery() != null && !parsed.getRawQuery().isEmpty()) {
                    path += "?" + parsed.getRawQuery();
                }
                return path;
            }
        } catch (Exception ignored) {
        }
        return uri.startsWith("/") ? uri : "/" + uri;
    }

    private static boolean isCursorApiHost(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        String lower = host.toLowerCase(Locale.ROOT);
        return lower.contains("cursor.sh") || lower.contains("cursorapi.com");
    }

    private static String extractHost(io.netty.handler.codec.http.HttpHeaders headers, String fallbackHost) {
        String host = headers == null ? null : headers.get(HttpHeaderNames.HOST);
        if (host == null || host.isEmpty()) {
            host = fallbackHost;
        }
        if (host == null) {
            return null;
        }
        host = host.trim();
        if (host.startsWith("http://") || host.startsWith("https://")) {
            try {
                java.net.URI uri = java.net.URI.create(host);
                if (uri.getHost() != null) {
                    host = uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "");
                }
            } catch (Exception ignored) {
            }
        }
        return host;
    }

    // ========================= RunSSE (AgentServerMessage) framing helpers =========================

    private static void writeConnectFrame(Channel clientChannel, byte[] wireFrame) {
        writeConnectFrameFuture(clientChannel, wireFrame);
    }

    private static ChannelFuture writeConnectFrameFuture(Channel clientChannel, byte[] wireFrame) {
        if (clientChannel == null || !clientChannel.isActive() || wireFrame == null || wireFrame.length == 0) {
            return null;
        }
        return clientChannel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(wireFrame)));
    }

    private static void finishChunkedResponse(Channel clientChannel, boolean keepAlive) {
        if (clientChannel == null) {
            return;
        }
        ChannelFuture f = clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);
        if (!keepAlive) {
            f.addListener(cf -> clientChannel.close());
        }
    }

    private static byte[] buildAgentTextDeltaFrame(String text) {
        try {
            byte[] textDelta = encodeLengthDelimitedField(1, utf8(text == null ? "" : text));
            byte[] interactionUpdate = encodeLengthDelimitedField(1, textDelta);
            byte[] agentServerMsg = encodeLengthDelimitedField(1, interactionUpdate);
            return buildWireFrame(0, agentServerMsg);
        } catch (IOException e) {
            return null;
        }
    }

    private static byte[] buildAgentTurnEndedFrame() {
        try {
            byte[] interactionUpdate = encodeLengthDelimitedField(14, new byte[0]);
            byte[] agentServerMsg = encodeLengthDelimitedField(1, interactionUpdate);
            return buildWireFrame(0, agentServerMsg);
        } catch (IOException e) {
            return null;
        }
    }

    private static byte[] buildConnectSuccessEndStreamFrame() {
        return buildWireFrame(2, utf8("{}"));
    }

    private static byte[] buildWireFrame(int typeByte, byte[] payload) {
        if (payload == null) {
            payload = new byte[0];
        }
        int len = payload.length;
        byte[] out = new byte[5 + len];
        out[0] = (byte) typeByte;
        out[1] = (byte) ((len >> 24) & 0xFF);
        out[2] = (byte) ((len >> 16) & 0xFF);
        out[3] = (byte) ((len >> 8) & 0xFF);
        out[4] = (byte) (len & 0xFF);
        System.arraycopy(payload, 0, out, 5, len);
        return out;
    }

    private static byte[] utf8(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] encodeLengthDelimitedField(int fieldNumber, byte[] payload) throws IOException {
        byte[] p = payload == null ? new byte[0] : payload;
        ByteArrayOutputStream out = new ByteArrayOutputStream(p.length + 8);
        writeVarint(out, (fieldNumber << 3) | 2);
        writeVarint(out, p.length);
        out.write(p);
        return out.toByteArray();
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
}

