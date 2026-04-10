package com.github.monkeywie.proxyee.intercept.cursor;

import com.github.monkeywie.proxyee.connect.ClientResponseGate;
import com.github.monkeywie.proxyee.connect.ConnectProtoUtil;
import com.github.monkeywie.proxyee.connect.AgentRunSseModelResolver;
import com.github.monkeywie.proxyee.connect.CursorConnectUpstreamCodec;
import com.github.monkeywie.proxyee.connect.CursorSessionModelCache;
import com.github.monkeywie.proxyee.connect.RunSseToUnifiedChatBodyConverter;
import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import io.netty.buffer.ByteBuf;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import io.netty.util.ReferenceCountUtil;

/**
 * 基于 proxyee MITM 的 Cursor 聊天拦截器：
 * 接收客户端解密后的 HTTP/1.1 请求，转为上游 HTTPS/HTTP2，并在流式响应中命中 abort token 时截断。
 */
public class CursorHttp2StreamAbortIntercept extends HttpProxyIntercept {

    private static final Logger LOG = Logger.getLogger(CursorHttp2StreamAbortIntercept.class.getName());
    private static final String DEBUG_LOG_PATH = "d:/devin/playgame/proxyee63/debug-064e27.log";
    private static final String DEBUG_RUNTIME_LOG_PATH = "D:/devin/playgame/proxyee63/debug-e2f75a.log";
    private static final String DEBUG_RUNTIME_SESSION_ID = "e2f75a";
    private static final int MAX_FULL_REQUEST_BYTES = 16 * 1024 * 1024;
    private static final String AGGREGATOR_NAME = "cursorProxyAggregator";
    private static final String UNIFIED_CHAT_UPSTREAM_URL =
            "https://api2.cursor.sh/aiserver.v1.ChatService/StreamUnifiedChatWithTools";
    private static final Pattern RICHTEXT_TEXT_PATTERN =
            Pattern.compile("\\\"text\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\\\\\"])*)\\\"");
    private static final Pattern LEADING_CONNECT_UUID_PREFIX_PATTERN =
            Pattern.compile("^(?:[\\u0000-\\u001F\\uFFFD]*\\$[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})+");
    private static final Pattern LEADING_CONTROL_GARBAGE_PATTERN =
            Pattern.compile("^[\\u0000-\\u001F\\uFFFD]+");
    private static final ConcurrentHashMap<String, String> SESSION_PROMPT_CACHE =
            new ConcurrentHashMap<String, String>();
    private static final ConcurrentHashMap<String, String> REQUEST_PROMPT_CACHE =
            new ConcurrentHashMap<String, String>();
    private static final ConcurrentHashMap<String, String> SESSION_RULES_CACHE =
            new ConcurrentHashMap<String, String>();
    private static final ConcurrentHashMap<String, String> REQUEST_RULES_CACHE =
            new ConcurrentHashMap<String, String>();

    public static final String DEFAULT_ABORT_TOKEN = "zmgnb666";

    private final byte[] abortTokenBytes;
    private final Consumer<HttpHeaders> headerModifier;
    private final OkHttpClient okHttpClient;

    private HttpProxyServer proxyServer;

    public CursorHttp2StreamAbortIntercept(String abortToken,
                                           Consumer<HttpHeaders> headerModifier) {
        String actualAbortToken = abortToken != null ? abortToken : DEFAULT_ABORT_TOKEN;
        this.abortTokenBytes = actualAbortToken.getBytes(StandardCharsets.UTF_8);
        this.headerModifier = headerModifier;
        this.okHttpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(180, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build();
    }

    public void start(int port) {
        HttpProxyServerConfig config = new HttpProxyServerConfig();
        config.setHandleSsl(true);
        config.setMitmMatcher(requestProto -> {
            String host = requestProto == null ? null : requestProto.getHost();
            if (host == null) {
                return false;
            }
            String lower = host.toLowerCase(Locale.ROOT);
            return lower.contains("cursor.sh") || lower.contains("cursorapi.com");
        });

        proxyServer = new HttpProxyServer()
                .serverConfig(config)
                .proxyInterceptInitializer(new HttpProxyInterceptInitializer() {
                    @Override
                    public void init(HttpProxyInterceptPipeline pipeline) {
                        pipeline.addLast(CursorHttp2StreamAbortIntercept.this);
                    }
                });

        proxyServer.startAsync(port).toCompletableFuture().join();
        LOG.info("[H2Proxy] MITM proxy started on port " + port);
        dl("CursorHttp2StreamAbortIntercept.start:" + port,
                "SERVER_STARTED",
                "{\"hypothesisId\":\"A\",\"port\":" + port + "}");
    }

    public void stop() {
        if (proxyServer != null) {
            proxyServer.close();
            proxyServer = null;
        }
        okHttpClient.dispatcher().executorService().shutdown();
        okHttpClient.connectionPool().evictAll();
    }

    @Override
    public void beforeRequest(Channel clientChannel, HttpRequest httpRequest,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        RouteKind routeKind = classifyRoute(httpRequest, pipeline);
        if (routeKind == RouteKind.PASSTHROUGH) {
            pipeline.beforeRequest(clientChannel, httpRequest);
            return;
        }

        if (!(httpRequest instanceof FullHttpRequest)) {
            ensureFullRequestAggregation(clientChannel, pipeline);
            clientChannel.pipeline().fireChannelRead(httpRequest);
            return;
        }

        removeAggregationHandlers(clientChannel);
        FullHttpRequest fullHttpRequest = (FullHttpRequest) httpRequest;
        if (routeKind == RouteKind.CACHE_BIDI_PASSTHROUGH) {
            cacheBidiContext(fullHttpRequest, pipeline);
            ReferenceCountUtil.retain(fullHttpRequest);
            pipeline.beforeRequest(clientChannel, (HttpRequest) fullHttpRequest);
            return;
        }
        DownstreamRequest snapshot = snapshotRequest(fullHttpRequest, pipeline);
        if (snapshot == null) {
            sendPlainAsync(clientChannel,
                    HttpResponseStatus.BAD_REQUEST,
                    "Invalid cursor request",
                    false);
            return;
        }

        dl("CursorHttp2StreamAbortIntercept.beforeRequest", "REQUEST_ACCEPTED",
                "{\"method\":\"" + snapshot.method
                        + "\",\"path\":\"" + esc(snapshot.normalizedPath)
                        + "\",\"upstreamUrl\":\"" + esc(snapshot.upstreamUrl)
                        + "\",\"contentLength\":" + snapshot.body.length + "}");
        if (snapshot.routeKind == RouteKind.BRIDGE_TO_UNIFIED_CHAT) {
            String bodyRequestId = extractRequestIdFromRunSseBody(snapshot.body);
            // #region agent log
            dbg(debugRunId(snapshot.headers, bodyRequestId), "H3",
                    "CursorHttp2StreamAbortIntercept.beforeRequest",
                    "bridge_request_observed",
                    "{\"path\":\"" + esc(snapshot.normalizedPath)
                            + "\",\"accept\":\"" + esc(headerFirst(snapshot.headers, "accept"))
                            + "\",\"contentType\":\"" + esc(headerFirst(snapshot.headers, "content-type"))
                            + "\",\"bodyLen\":" + snapshot.body.length
                            + ",\"requestId\":\"" + esc(bodyRequestId)
                            + "\",\"sessionId\":\"" + esc(headerFirst(snapshot.headers, "x-session-id"))
                            + "\"}");
            // #endregion
        }
        printHeaders("[H2Proxy] Client Req Headers", snapshot.headers);
        if (snapshot.body.length > 0) {
            LOG.info("[H2Proxy] Client Req Body: " + snapshot.body.length
                    + " bytes, hex=" + hexPrefix(snapshot.body, 120));
        }

        ClientResponseGate gate = ClientResponseGate.forChannel(clientChannel);
        gate.enterOrEnqueue(() -> executeInterceptedRequest(clientChannel, snapshot));
    }

    // ================================================================
    //  请求处理
    // ================================================================

    private void executeInterceptedRequest(Channel clientChannel, DownstreamRequest request) {
        if (!clientChannel.isActive()) {
            completeCurrentResponse(clientChannel);
            return;
        }

        try {
            Request upstreamRequest = buildUpstreamRequest(request);
            dl("CursorHttp2StreamAbortIntercept.beforeUpstream", "UPSTREAM_REQUEST_PREPARED",
                    "{\"upstreamUrl\":\"" + esc(request.upstreamUrl)
                            + "\",\"bodyLen\":" + request.body.length
                            + ",\"streaming\":" + request.abortAware
                            + ",\"abortAware\":" + request.abortAware + "}");

            LOG.info("[H2Proxy] >>> Upstream: " + request.method + " " + request.upstreamUrl);
            printOkHeaders("[H2Proxy] Upstream Req Headers", upstreamRequest.headers());

            Call call = okHttpClient.newCall(upstreamRequest);
            clientChannel.closeFuture().addListener(f -> call.cancel());
            call.enqueue(new Callback() {
                @Override
                public void onResponse(Call call, Response response) {
                    dl("OkHttp.onResponse", "UPSTREAM_RESPONSE",
                            "{\"statusCode\":" + response.code()
                                    + ",\"protocol\":\"" + response.protocol()
                                    + "\",\"contentType\":\""
                                    + esc(response.header("content-type")) + "\"}");
                    handleUpstreamResponse(call, response, clientChannel, request);
                }

                @Override
                public void onFailure(Call call, IOException e) {
                    dl("OkHttp.onFailure", "UPSTREAM_FAILED",
                            "{\"error\":\"" + esc(e.getClass().getSimpleName() + ": " + e.getMessage())
                                    + "\",\"canceled\":" + call.isCanceled() + "}");
                    if (call.isCanceled()) {
                        completeCurrentResponse(clientChannel);
                        return;
                    }
                    LOG.log(Level.SEVERE, "[H2Proxy] Upstream request failed", e);
                    sendPlainAsync(clientChannel,
                            HttpResponseStatus.BAD_GATEWAY,
                            "Upstream failed: " + e.getMessage(),
                            request.keepAlive);
                }
            });
        } catch (Exception e) {
            if (isExpectedMissingBidiPrompt(e)) {
                LOG.info("[H2Proxy] Skip early RunSSE without cached Bidi prompt: " + e.getMessage());
            } else {
                LOG.log(Level.SEVERE, "[H2Proxy] Build upstream request failed", e);
            }
            sendPlainAsync(clientChannel,
                    HttpResponseStatus.BAD_GATEWAY,
                    "Proxy build failed: " + e.getMessage(),
                    request.keepAlive);
        }
    }

    private Request buildUpstreamRequest(DownstreamRequest request) {
        HttpHeaders forwarded = buildForwardHeaders(request);
        MediaType mediaType = parseMediaType(forwarded.get(HttpHeaderNames.CONTENT_TYPE));
        RequestBody body = RequestBody.create(mediaType, buildUpstreamBody(request));
        Request.Builder builder = new Request.Builder()
                .url(request.upstreamUrl)
                .method(request.method, body);

        for (Map.Entry<String, String> e : forwarded) {
            builder.addHeader(e.getKey(), e.getValue());
        }
        return builder.build();
    }

    // ================================================================
    //  上游响应处理
    // ================================================================

    private void handleUpstreamResponse(Call call, Response response, Channel clientChannel,
                                        DownstreamRequest request) {
        try {
            if (!clientChannel.isActive()) {
                response.close();
                completeCurrentResponse(clientChannel);
                return;
            }

            int status = response.code();
            LOG.info("[H2Proxy] <<< Upstream Resp: " + status + " " + response.protocol());
            printOkHeaders("[H2Proxy] Upstream Resp Headers", response.headers());

            if (status != 200) {
                sendErrorResponse(clientChannel, response, request.keepAlive);
                return;
            }

            ResponseBody body = response.body();
            DefaultHttpResponse downstreamHead = new DefaultHttpResponse(
                    HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(status));
            if (request.routeKind == RouteKind.BRIDGE_TO_UNIFIED_CHAT) {
                initBridgedRunSseHeaders(request, downstreamHead.headers());
                // #region agent log
                dbg(debugRunId(request.headers, extractRequestIdFromRunSseBody(request.body)), "H3",
                        "CursorHttp2StreamAbortIntercept.handleUpstreamResponse",
                        "bridge_downstream_headers",
                        "{\"upstreamContentType\":\"" + esc(response.header("content-type"))
                                + "\",\"downstreamContentType\":\""
                                + esc(downstreamHead.headers().get(HttpHeaderNames.CONTENT_TYPE))
                                + "\",\"status\":" + status + "}");
                // #endregion
            } else {
                copyDownstreamHeaders(response.headers(), downstreamHead.headers());
            }
            downstreamHead.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
            HttpUtil.setKeepAlive(downstreamHead, request.keepAlive);

            clientChannel.writeAndFlush(downstreamHead);
            LOG.info("[H2Proxy] >>> Client: HTTP/1.1 " + status + " chunked");

            if (body == null) {
                finishChunkedResponse(clientChannel, request.keepAlive);
                response.close();
                return;
            }

            if (request.routeKind == RouteKind.BRIDGE_TO_UNIFIED_CHAT) {
                streamUnifiedChatAsAgentRunSse(call, body, clientChannel, request.keepAlive);
            } else if (request.abortAware) {
                streamWithAbortDetection(call, body, clientChannel, request.keepAlive);
            } else {
                streamRawBody(body, clientChannel, request.keepAlive);
            }
        } catch (Exception e) {
            response.close();
            LOG.log(Level.SEVERE, "[H2Proxy] handleUpstreamResponse error", e);
            sendPlainAsync(clientChannel,
                    HttpResponseStatus.BAD_GATEWAY,
                    "Upstream handling failed: " + e.getMessage(),
                    request.keepAlive);
        }
    }

    private void sendErrorResponse(Channel clientChannel, Response response, boolean keepAlive)
            throws IOException {
        ResponseBody body = response.body();
        byte[] errBytes = body != null ? body.bytes() : new byte[0];
        FullHttpResponse fullResp = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.valueOf(response.code()),
                Unpooled.wrappedBuffer(errBytes));
        copyDownstreamHeaders(response.headers(), fullResp.headers());
        fullResp.headers().set(HttpHeaderNames.CONTENT_LENGTH, errBytes.length);
        HttpUtil.setKeepAlive(fullResp, keepAlive);
        writeAndFinalize(clientChannel, fullResp, keepAlive);
    }

    // ================================================================
    //  流式响应处理
    // ================================================================

    private void streamRawBody(ResponseBody body, Channel clientChannel, boolean keepAlive) {
        try (InputStream is = body.byteStream()) {
            byte[] buf = new byte[8192];
            int n;
            while (clientChannel.isActive() && (n = is.read(buf)) != -1) {
                clientChannel.writeAndFlush(new DefaultHttpContent(
                        Unpooled.copiedBuffer(buf, 0, n)));
            }
            finishChunkedResponse(clientChannel, keepAlive);
        } catch (IOException e) {
            LOG.log(Level.WARNING, "[H2Proxy] Raw stream read error", e);
            finishChunkedResponse(clientChannel, keepAlive);
        }
    }

    private void streamUnifiedChatAsAgentRunSse(Call call, ResponseBody body,
                                                Channel clientChannel, boolean keepAlive) {
        boolean trailerForwarded = false;
        boolean turnEndedSent = false;
        boolean firstFrameLogged = false;
        int totalFrames = 0;
        int dataFrames = 0;
        int textFrames = 0;
        int responseKindLogs = 0;
        String abortToken = new String(abortTokenBytes, StandardCharsets.UTF_8);
        StringBuilder emittedTextWindow = new StringBuilder();
        try (InputStream is = body.byteStream();
             DataInputStream dis = new DataInputStream(new BufferedInputStream(is))) {
            int frameIdx = 0;
            while (clientChannel.isActive()) {
                int typeByte;
                try {
                    typeByte = dis.readUnsignedByte();
                } catch (EOFException eof) {
                    break;
                }

                int payloadLen = dis.readInt();
                if (payloadLen < 0 || payloadLen > ConnectProtoUtil.MAX_CONNECT_PAYLOAD_LEN) {
                    LOG.warning("[H2Proxy] Bad frame payload length: " + payloadLen);
                    break;
                }

                byte[] payload = new byte[payloadLen];
                dis.readFully(payload);
                byte[] wire = buildWireFrame(typeByte, payload);
                totalFrames++;

                boolean compressed = (typeByte & 1) != 0;
                int msgType = typeByte >> 1;
                if (msgType == 0) {
                    dataFrames++;
                    byte[] decompressed = compressed
                            ? ConnectProtoUtil.gzipDecompress(payload) : payload;
                    if (decompressed == null) {
                        frameIdx++;
                        continue;
                    }

                    byte[] effectivePayload = decompressed;
                    int needleIdx = ConnectProtoUtil.indexOfSubsequence(decompressed, abortTokenBytes);
                    if (needleIdx >= 0) {
                        byte[] prefix = Arrays.copyOfRange(decompressed, 0, needleIdx);
                        boolean isAssistant =
                                ConnectProtoUtil.lastRoleBeforeNeedleIsAssistant(prefix);
                        if (isAssistant) {
                            LOG.info("[H2Proxy] *** ABORT TOKEN matched at bridged frame#" + frameIdx + " ***");
                            byte[] cleanedWire = ConnectProtoUtil.removeAbortTokenFromWire(
                                    wire, abortTokenBytes);
                            if (cleanedWire != null) {
                                byte[] cleanedPayload = ConnectProtoUtil.extractPayloadFromWire(cleanedWire);
                                if (cleanedPayload != null) {
                                    effectivePayload = cleanedPayload;
                                }
                            }
                            String text = sanitizeAssistantText(
                                    ConnectProtoUtil.extractVisibleTextFromUnifiedChatResponse(effectivePayload));
                            byte[] turnEndedFrame = buildAgentTurnEndedFrame();
                            byte[] connectTrailerFrame = buildConnectSuccessEndStreamFrame();
                            // #region agent log
                            dbg("abort-finalize", "H10",
                                    "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                    "abort_finalize_plan",
                                    "{\"frameIdx\":" + frameIdx
                                            + ",\"reason\":\"raw_assistant_abort\""
                                            + ",\"forwardTextLen\":" + (text == null ? 0 : text.length())
                                            + ",\"turnEndedLen\":" + (turnEndedFrame == null ? 0 : turnEndedFrame.length)
                                            + ",\"connectTrailerLen\":" + (connectTrailerFrame == null ? 0 : connectTrailerFrame.length)
                                            + ",\"sendConnectTrailer\":true"
                                            + ",\"finishWithHttpLastContent\":true}");
                            // #endregion
                            if (text != null && !text.isEmpty()) {
                                writeConnectFrame(clientChannel, buildAgentTextDeltaFrame(text));
                            }
                            if (!turnEndedSent) {
                                ChannelFuture turnEndedFuture = writeConnectFrameFuture(clientChannel, turnEndedFrame);
                                if (turnEndedFuture != null) {
                                    turnEndedFuture.addListener(f -> {
                                        // #region agent log
                                        dbg("abort-finalize", "H11",
                                                "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                                "abort_turn_ended_flush_done",
                                                "{\"reason\":\"raw_assistant_abort\""
                                                        + ",\"success\":" + f.isSuccess()
                                                        + ",\"cause\":\""
                                                        + esc(f.cause() == null ? null : String.valueOf(f.cause()))
                                                        + "\"}");
                                        // #endregion
                                    });
                                }
                                turnEndedSent = true;
                            }
                            ChannelFuture connectTrailerFuture =
                                    writeConnectFrameFuture(clientChannel, connectTrailerFrame);
                            if (connectTrailerFuture != null) {
                                connectTrailerFuture.addListener(f -> {
                                    // #region agent log
                                    dbg("abort-finalize", "H12",
                                            "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                            "abort_connect_trailer_flush_done",
                                            "{\"reason\":\"raw_assistant_abort\""
                                                    + ",\"success\":" + f.isSuccess()
                                                    + ",\"cause\":\""
                                                    + esc(f.cause() == null ? null : String.valueOf(f.cause()))
                                                    + "\"}");
                                    // #endregion
                                });
                            }
                            call.cancel();
                            finishChunkedResponseTracked(clientChannel, keepAlive,
                                    "abort-finalize", "H11", "raw_assistant_abort");
                            return;
                        }
                    }

                    String responseKind = ConnectProtoUtil.describeUnifiedChatResponseKind(effectivePayload);
                    if (responseKindLogs < 24) {
                        String toolSummary = ConnectProtoUtil.extractUnifiedChatToolCallSummary(effectivePayload);
                        // #region agent log
                        dbg("bridge-stream", "H_RESP",
                                "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                "bridge_response_frame_kind",
                                "{\"frameIdx\":" + frameIdx
                                        + ",\"kind\":\"" + esc(responseKind)
                                        + "\",\"toolSummary\":\"" + esc(oneLinePreview(toolSummary, 240))
                                        + "\",\"compressed\":" + compressed
                                        + ",\"payloadLen\":" + effectivePayload.length + "}");
                        // #endregion
                        responseKindLogs++;
                    }
                    String rawText = ConnectProtoUtil.extractVisibleTextFromUnifiedChatResponse(effectivePayload);
                    String text = sanitizeAssistantText(rawText);
                    if (text != null && !text.isEmpty()) {
                        emittedTextWindow.append(text);
                        if (emittedTextWindow.length() > 4096) {
                            emittedTextWindow.delete(0, emittedTextWindow.length() - 4096);
                        }
                        if (emittedTextWindow.indexOf(abortToken) >= 0) {
                            String beforeToken = emittedTextWindow.substring(0, emittedTextWindow.indexOf(abortToken));
                            String currentPrefix = beforeToken.length() > 0 && beforeToken.length() >= text.length()
                                    ? beforeToken.substring(Math.max(0, beforeToken.length() - text.length()))
                                    : beforeToken;
                            String safeCurrent = text;
                            if (currentPrefix != null && !currentPrefix.isEmpty()
                                    && safeCurrent.startsWith(currentPrefix)) {
                                safeCurrent = safeCurrent.substring(currentPrefix.length());
                            }
                            int abortInCurrent = safeCurrent.indexOf(abortToken);
                            String forwardText = abortInCurrent >= 0
                                    ? safeCurrent.substring(0, abortInCurrent)
                                    : "";
                            // #region agent log
                            dbg("abort-scan", "H9",
                                    "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                    "abort_token_detected_in_emitted_text",
                                    "{\"frameIdx\":" + frameIdx
                                            + ",\"windowPreview\":\""
                                            + esc(oneLinePreview(emittedTextWindow.toString(), 200))
                                            + "\",\"forwardTextPreview\":\""
                                            + esc(oneLinePreview(forwardText, 120)) + "\"}");
                            // #endregion
                            byte[] turnEndedFrame = buildAgentTurnEndedFrame();
                            byte[] connectTrailerFrame = buildConnectSuccessEndStreamFrame();
                            // #region agent log
                            dbg("abort-finalize", "H10",
                                    "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                    "abort_finalize_plan",
                                    "{\"frameIdx\":" + frameIdx
                                            + ",\"reason\":\"emitted_text_abort\""
                                            + ",\"forwardTextLen\":" + forwardText.length()
                                            + ",\"turnEndedLen\":" + (turnEndedFrame == null ? 0 : turnEndedFrame.length)
                                            + ",\"connectTrailerLen\":" + (connectTrailerFrame == null ? 0 : connectTrailerFrame.length)
                                            + ",\"sendConnectTrailer\":true"
                                            + ",\"finishWithHttpLastContent\":true}");
                            // #endregion
                            if (!forwardText.isEmpty()) {
                                writeConnectFrame(clientChannel, buildAgentTextDeltaFrame(forwardText));
                            }
                            if (!turnEndedSent) {
                                ChannelFuture turnEndedFuture = writeConnectFrameFuture(clientChannel, turnEndedFrame);
                                if (turnEndedFuture != null) {
                                    turnEndedFuture.addListener(f -> {
                                        // #region agent log
                                        dbg("abort-finalize", "H11",
                                                "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                                "abort_turn_ended_flush_done",
                                                "{\"reason\":\"emitted_text_abort\""
                                                        + ",\"success\":" + f.isSuccess()
                                                        + ",\"cause\":\""
                                                        + esc(f.cause() == null ? null : String.valueOf(f.cause()))
                                                        + "\"}");
                                        // #endregion
                                    });
                                }
                                turnEndedSent = true;
                            }
                            ChannelFuture connectTrailerFuture =
                                    writeConnectFrameFuture(clientChannel, connectTrailerFrame);
                            if (connectTrailerFuture != null) {
                                connectTrailerFuture.addListener(f -> {
                                    // #region agent log
                                    dbg("abort-finalize", "H12",
                                            "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                            "abort_connect_trailer_flush_done",
                                            "{\"reason\":\"emitted_text_abort\""
                                                    + ",\"success\":" + f.isSuccess()
                                                    + ",\"cause\":\""
                                                    + esc(f.cause() == null ? null : String.valueOf(f.cause()))
                                                    + "\"}");
                                    // #endregion
                                });
                            }
                            call.cancel();
                            finishChunkedResponseTracked(clientChannel, keepAlive,
                                    "abort-finalize", "H11", "emitted_text_abort");
                            return;
                        }
                        textFrames++;
                        LOG.info("[H2Proxy] Bridged Frame#" + frameIdx
                                + " text(" + text.length() + "): " + trunc(text, 300));
                        if (!firstFrameLogged) {
                            firstFrameLogged = true;
                            byte[] clientWire = buildAgentTextDeltaFrame(text);
                            // #region agent log
                            dbg("bridge-stream", "H4",
                                    "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                                    "bridge_first_text_frame",
                                    "{\"frameIdx\":" + frameIdx
                                            + ",\"kind\":\"" + esc(responseKind)
                                            + ",\"compressed\":" + compressed
                                            + ",\"rawUpstreamTextPreview\":\"" + esc(oneLinePreview(rawText, 120))
                                            + "\",\"sanitizedTextPreview\":\"" + esc(oneLinePreview(text, 120))
                                            + "\",\"clientWireLen\":" + (clientWire == null ? 0 : clientWire.length)
                                            + "}");
                            // #endregion
                            writeConnectFrame(clientChannel, clientWire);
                        } else {
                            writeConnectFrame(clientChannel, buildAgentTextDeltaFrame(text));
                        }
                    }
                } else if (msgType == 1) {
                    if (!turnEndedSent) {
                        writeConnectFrame(clientChannel, buildAgentTurnEndedFrame());
                        turnEndedSent = true;
                    }
                    writeConnectFrame(clientChannel, wire);
                    trailerForwarded = true;
                }
                frameIdx++;
            }

            // #region agent log
            dbg("bridge-stream", "H4",
                    "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                    "bridge_stream_summary",
                    "{\"totalFrames\":" + totalFrames
                            + ",\"dataFrames\":" + dataFrames
                            + ",\"textFrames\":" + textFrames
                            + ",\"trailerForwarded\":" + trailerForwarded
                            + ",\"turnEndedSent\":" + turnEndedSent + "}");
            // #endregion
            if (!turnEndedSent) {
                writeConnectFrame(clientChannel, buildAgentTurnEndedFrame());
            }
            if (!trailerForwarded) {
                // Cursor 的 RunSSE 末尾通常还会跟一个 connect trailer；这里没有上游 trailer 时直接靠 HTTP 结束。
            }
            finishChunkedResponse(clientChannel, keepAlive);
        } catch (IOException e) {
            if (!call.isCanceled()) {
                LOG.log(Level.WARNING, "[H2Proxy] Bridged stream read error", e);
            }
            // #region agent log
            dbg("bridge-stream", "H4",
                    "CursorHttp2StreamAbortIntercept.streamUnifiedChatAsAgentRunSse",
                    "bridge_stream_ioexception",
                    "{\"totalFrames\":" + totalFrames
                            + ",\"dataFrames\":" + dataFrames
                            + ",\"textFrames\":" + textFrames
                            + ",\"error\":\"" + esc(e.getClass().getSimpleName() + ":" + e.getMessage()) + "\"}");
            // #endregion
            if (!turnEndedSent && clientChannel.isActive()) {
                writeConnectFrame(clientChannel, buildAgentTurnEndedFrame());
            }
            finishChunkedResponse(clientChannel, keepAlive);
        }
    }

    private void streamWithAbortDetection(Call call, ResponseBody body,
                                          Channel clientChannel, boolean keepAlive) {
        try (InputStream is = body.byteStream();
             DataInputStream dis = new DataInputStream(new BufferedInputStream(is))) {
            int frameIdx = 0;
            StringBuilder assistantWindow = new StringBuilder();
            StringBuilder assistantWindowNoSep = new StringBuilder();
            while (clientChannel.isActive()) {
                int typeByte;
                try {
                    typeByte = dis.readUnsignedByte();
                } catch (EOFException eof) {
                    break;
                }

                int payloadLen = dis.readInt();
                if (payloadLen < 0 || payloadLen > ConnectProtoUtil.MAX_CONNECT_PAYLOAD_LEN) {
                    LOG.warning("[H2Proxy] Bad frame payload length: " + payloadLen);
                    break;
                }

                byte[] payload = new byte[payloadLen];
                dis.readFully(payload);
                byte[] wire = buildWireFrame(typeByte, payload);

                boolean compressed = (typeByte & 1) != 0;
                int msgType = typeByte >> 1;
                if (msgType == 0) {
                    byte[] decompressed = compressed
                            ? ConnectProtoUtil.gzipDecompress(payload) : payload;
                    if (decompressed != null) {
                        String text = ConnectProtoUtil.extractTextFromResponseLenient(decompressed);
                        if (text != null && !text.isEmpty()) {
                            String sanitized = sanitizeAssistantText(text);
                            if (sanitized != null && !sanitized.isEmpty()) {
                                if (assistantWindow.length() > 0 && assistantWindow.length() < 4096) {
                                    assistantWindow.append('\n');
                                }
                                assistantWindow.append(sanitized);
                                if (assistantWindow.length() > 4096) {
                                    assistantWindow.delete(0, assistantWindow.length() - 4096);
                                }
                                assistantWindowNoSep.append(sanitized);
                                if (assistantWindowNoSep.length() > 4096) {
                                    assistantWindowNoSep.delete(0, assistantWindowNoSep.length() - 4096);
                                }
                                if (assistantWindow.indexOf(new String(abortTokenBytes, StandardCharsets.UTF_8)) >= 0) {
                                    // #region agent log
                                    dbg("abort-scan", "H8",
                                            "CursorHttp2StreamAbortIntercept.streamWithAbortDetection",
                                            "abort_token_seen_in_accumulated_window",
                                            "{\"frameIdx\":" + frameIdx
                                                    + ",\"windowPreview\":\""
                                                    + esc(oneLinePreview(assistantWindow.toString(), 200)) + "\"}");
                                    // #endregion
                                }
                                if (assistantWindowNoSep.indexOf(new String(abortTokenBytes, StandardCharsets.UTF_8)) >= 0) {
                                    // #region agent log
                                    dbg("abort-scan", "H8",
                                            "CursorHttp2StreamAbortIntercept.streamWithAbortDetection",
                                            "abort_token_seen_in_accumulated_window_no_sep",
                                            "{\"frameIdx\":" + frameIdx
                                                    + ",\"windowPreview\":\""
                                                    + esc(oneLinePreview(assistantWindowNoSep.toString(), 200)) + "\"}");
                                    // #endregion
                                }
                            }
                            LOG.info("[H2Proxy] Frame#" + frameIdx
                                    + " text(" + text.length() + "): " + trunc(text, 300));
                        }
                        int needleIdx = ConnectProtoUtil.indexOfSubsequence(
                                decompressed, abortTokenBytes);
                        if (needleIdx >= 0) {
                            byte[] prefix = Arrays.copyOfRange(decompressed, 0, needleIdx);
                            boolean isAssistant =
                                    ConnectProtoUtil.lastRoleBeforeNeedleIsAssistant(prefix);
                            // #region agent log
                            dbg("abort-scan", "H7",
                                    "CursorHttp2StreamAbortIntercept.streamWithAbortDetection",
                                    "abort_token_detected",
                                    "{\"frameIdx\":" + frameIdx
                                            + ",\"needleIdx\":" + needleIdx
                                            + ",\"compressed\":" + compressed
                                            + ",\"isAssistant\":" + isAssistant
                                            + ",\"textPreview\":\""
                                            + esc(oneLinePreview(sanitizeAssistantText(text), 160)) + "\"}");
                            // #endregion
                            if (isAssistant) {
                                LOG.info("[H2Proxy] *** ABORT TOKEN matched at frame#" + frameIdx + " ***");
                                byte[] cleaned = ConnectProtoUtil.removeAbortTokenFromWire(
                                        wire, abortTokenBytes);
                                if (cleaned != null && cleaned.length > 5) {
                                    clientChannel.writeAndFlush(new DefaultHttpContent(
                                            Unpooled.wrappedBuffer(cleaned)));
                                    LOG.info("[H2Proxy] Forwarded cleaned frame (" + cleaned.length + " bytes)");
                                }
                                call.cancel();
                                LOG.info("[H2Proxy] Upstream RST sent (call.cancel)");
                                finishChunkedResponse(clientChannel, keepAlive);
                                return;
                            }
                            // #region agent log
                            dbg("abort-scan", "H7",
                                    "CursorHttp2StreamAbortIntercept.streamWithAbortDetection",
                                    "abort_token_ignored_non_assistant",
                                    "{\"frameIdx\":" + frameIdx
                                            + ",\"needleIdx\":" + needleIdx
                                            + ",\"textPreview\":\""
                                            + esc(oneLinePreview(sanitizeAssistantText(text), 160)) + "\"}");
                            // #endregion
                            LOG.info("[H2Proxy] Abort token in rule/thinking, ignoring");
                        }
                    }
                }
                clientChannel.writeAndFlush(new DefaultHttpContent(
                        Unpooled.wrappedBuffer(wire)));
                frameIdx++;
            }
            LOG.info("[H2Proxy] Stream complete, total frames=" + frameIdx);
            finishChunkedResponse(clientChannel, keepAlive);
        } catch (IOException e) {
            if (!call.isCanceled()) {
                LOG.log(Level.WARNING, "[H2Proxy] Stream read error", e);
            }
            finishChunkedResponse(clientChannel, keepAlive);
        }
    }

    // ================================================================
    //  请求识别 / 归一化
    // ================================================================

    private RouteKind classifyRoute(HttpRequest request, HttpProxyInterceptPipeline pipeline) {
        if (request == null || !HttpMethod.POST.equals(request.method())) {
            return RouteKind.PASSTHROUGH;
        }
        String hostFallback = pipeline.getRequestProto() == null
                ? null : pipeline.getRequestProto().getHost();
        String host = extractHost(request.headers(), hostFallback);
        if (!isCursorApiHost(host)) {
            return RouteKind.PASSTHROUGH;
        }
        String path = normalizePath(request.uri());
        if (path.contains("BidiAppend")) {
            return RouteKind.CACHE_BIDI_PASSTHROUGH;
        }
        if (path.contains("RunSSE")) {
            return RouteKind.BRIDGE_TO_UNIFIED_CHAT;
        }
        if (path.contains("StreamUnifiedChat")) {
            return RouteKind.PROXY_HTTP2_DIRECT;
        }
        return RouteKind.PASSTHROUGH;
    }

    private DownstreamRequest snapshotRequest(FullHttpRequest request,
                                              HttpProxyInterceptPipeline pipeline) {
        String normalizedPath = normalizePath(request.uri());
        String hostFallback = pipeline.getRequestProto() == null
                ? null : pipeline.getRequestProto().getHost();
        String host = extractHost(request.headers(), hostFallback);
        if (host == null || host.isEmpty()) {
            LOG.warning("[H2Proxy] Missing host for intercepted request");
            return null;
        }
        byte[] body = extractBody(request);
        RouteKind routeKind = classifyRoute(request, pipeline);
        String upstreamUrl = routeKind == RouteKind.BRIDGE_TO_UNIFIED_CHAT
                ? UNIFIED_CHAT_UPSTREAM_URL
                : "https://" + host + normalizedPath;
        return new DownstreamRequest(
                request.method().name(),
                normalizedPath,
                upstreamUrl,
                copyHeaders(request.headers()),
                body,
                HttpUtil.isKeepAlive(request),
                isAbortAwarePath(normalizedPath),
                routeKind
        );
    }

    private static String normalizePath(String uri) {
        if (uri == null || uri.isEmpty()) {
            return "/";
        }
        try {
            URI parsed = URI.create(uri);
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

    private static boolean isAbortAwarePath(String uri) {
        if (uri == null) {
            return false;
        }
        return uri.contains("RunSSE") || uri.contains("StreamUnifiedChat");
    }

    // ================================================================
    //  header / body 辅助
    // ================================================================

    private static HttpHeaders copyHeaders(HttpHeaders headers) {
        io.netty.handler.codec.http.DefaultHttpHeaders copy =
                new io.netty.handler.codec.http.DefaultHttpHeaders();
        for (Map.Entry<String, String> e : headers) {
            copy.add(e.getKey(), e.getValue());
        }
        return copy;
    }

    private static String extractHost(HttpHeaders headers, String fallbackHost) {
        String host = headers.get(HttpHeaderNames.HOST);
        if (host == null || host.isEmpty()) {
            host = fallbackHost;
        }
        if (host == null) {
            return null;
        }
        host = host.trim();
        if (host.startsWith("http://") || host.startsWith("https://")) {
            try {
                URI uri = URI.create(host);
                if (uri.getHost() != null) {
                    host = uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "");
                }
            } catch (Exception ignored) {
            }
        }
        return host;
    }

    private static void stripHopByHopRequestHeaders(HttpHeaders headers) {
        headers.remove(HttpHeaderNames.HOST);
        headers.remove(HttpHeaderNames.CONNECTION);
        headers.remove(HttpHeaderNames.PROXY_CONNECTION);
        headers.remove(HttpHeaderNames.KEEP_ALIVE);
        headers.remove(HttpHeaderNames.TRANSFER_ENCODING);
        headers.remove(HttpHeaderNames.CONTENT_LENGTH);
        headers.remove(HttpHeaderNames.TE);
        headers.remove(HttpHeaderNames.TRAILER);
        headers.remove(HttpHeaderNames.UPGRADE);
    }

    private static void copyDownstreamHeaders(Headers from, HttpHeaders to) {
        for (int i = 0; i < from.size(); i++) {
            String name = from.name(i);
            if (isHopByHopResponseHeader(name)) {
                continue;
            }
            to.add(name, from.value(i));
        }
    }

    private static boolean isHopByHopResponseHeader(String name) {
        if (name == null) {
            return true;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        return "connection".equals(lower)
                || "keep-alive".equals(lower)
                || "proxy-connection".equals(lower)
                || "transfer-encoding".equals(lower)
                || "content-length".equals(lower)
                || "te".equals(lower)
                || "trailer".equals(lower)
                || "upgrade".equals(lower);
    }

    private static MediaType parseMediaType(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return null;
        }
        try {
            return MediaType.parse(raw);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static byte[] extractBody(FullHttpRequest request) {
        if (!request.content().isReadable()) {
            return new byte[0];
        }
        byte[] bytes = new byte[request.content().readableBytes()];
        request.content().getBytes(request.content().readerIndex(), bytes);
        return bytes;
    }

    private static byte[] buildWireFrame(int typeByte, byte[] payload) {
        byte[] wire = new byte[5 + payload.length];
        wire[0] = (byte) typeByte;
        wire[1] = (byte) ((payload.length >> 24) & 0xFF);
        wire[2] = (byte) ((payload.length >> 16) & 0xFF);
        wire[3] = (byte) ((payload.length >> 8) & 0xFF);
        wire[4] = (byte) (payload.length & 0xFF);
        System.arraycopy(payload, 0, wire, 5, payload.length);
        return wire;
    }

    private static void initBridgedRunSseHeaders(DownstreamRequest request, HttpHeaders headers) {
        headers.set(HttpHeaderNames.CONTENT_TYPE, runSseContentType(request.headers));
        headers.set("connect-protocol-version", "1");
        headers.remove("connect-content-encoding");
        headers.remove(HttpHeaderNames.CONTENT_ENCODING);
        headers.set(HttpHeaderNames.CACHE_CONTROL, "no-cache");
    }

    private static String runSseContentType(HttpHeaders requestHeaders) {
        return "application/connect+proto";
    }

    private static void writeConnectFrame(Channel clientChannel, byte[] wireFrame) {
        writeConnectFrameFuture(clientChannel, wireFrame);
    }

    private static ChannelFuture writeConnectFrameFuture(Channel clientChannel, byte[] wireFrame) {
        if (wireFrame == null || wireFrame.length == 0 || !clientChannel.isActive()) {
            return null;
        }
        return clientChannel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(wireFrame)));
    }

    private HttpHeaders buildForwardHeaders(DownstreamRequest request) {
        HttpHeaders forwarded;
        if (request.routeKind == RouteKind.BRIDGE_TO_UNIFIED_CHAT) {
            String bearerToken = CursorConnectUpstreamCodec.parseBearerToken(request.headers);
            if (bearerToken == null || bearerToken.isEmpty()) {
                throw new IllegalArgumentException("Missing Authorization Bearer");
            }
            forwarded = CursorConnectUpstreamCodec.hybridUpstreamHeadersForUnifiedChat(
                    request.headers, bearerToken);
        } else {
            forwarded = copyHeaders(request.headers);
            stripHopByHopRequestHeaders(forwarded);
        }
        if (headerModifier != null) {
            headerModifier.accept(forwarded);
        }
        return forwarded;
    }

    private byte[] buildUpstreamBody(DownstreamRequest request) {
        if (request.routeKind != RouteKind.BRIDGE_TO_UNIFIED_CHAT) {
            return request.body;
        }
        try {
            String cachedPrompt = findCachedPrompt(request);
            String runId = debugRunId(request.headers, extractRequestIdFromRunSseBody(request.body));
            String sessionModel = CursorSessionModelCache.getIfPresent(request.headers);
            AgentRunSseModelResolver.ModelResolution resolution =
                    AgentRunSseModelResolver.resolveDetail(request.headers, request.normalizedPath, request.body);
            // #region agent log
            dbg(runId, "H2",
                    "CursorHttp2StreamAbortIntercept.buildUpstreamBody",
                    "bridge_body_inputs",
                    "{\"resolverModel\":\"" + esc(resolution.model)
                            + "\",\"resolverSource\":\"" + esc(resolution.source)
                            + "\",\"sessionCacheModel\":\"" + esc(sessionModel)
                            + "\",\"cachedPromptLen\":" + (cachedPrompt == null ? 0 : cachedPrompt.length())
                            + ",\"cachedPromptPreview\":\"" + esc(oneLinePreview(cachedPrompt, 120))
                            + "\"}");
            // #endregion
            if ((cachedPrompt == null || cachedPrompt.trim().isEmpty())
                    && isRequestIdOnlyRunSseBody(request.body)) {
                // #region agent log
                dbg(runId, "H1",
                        "CursorHttp2StreamAbortIntercept.buildUpstreamBody",
                        "reject_request_id_only_runsse",
                        "{\"reason\":\"runsse_body_only_request_id_without_bidi_prompt\"}");
                // #endregion
                throw new IllegalStateException("RunSSE body only carries requestId; missing BidiAppend prompt");
            }
            if (cachedPrompt != null && !cachedPrompt.trim().isEmpty()) {
                String model = chooseBridgedModel(sessionModel, resolution);
                String extraSystemPrompt = findCachedRulesContext(request);
                byte[] built = CursorConnectUpstreamCodec.buildFramedUnifiedChatBody(
                        model, cachedPrompt, extraSystemPrompt);
                // #region agent log
                dbg(runId, "H2",
                        "CursorHttp2StreamAbortIntercept.buildUpstreamBody",
                        "bridge_body_output_bidi_cache",
                        "{\"finalModel\":\"" + esc(model)
                                + "\",\"promptSource\":\"bidi_cache"
                                + "\",\"promptPreview\":\"" + esc(oneLinePreview(cachedPrompt, 120))
                                + "\",\"rulesContextLen\":" + (extraSystemPrompt == null ? 0 : extraSystemPrompt.length())
                                + ",\"rulesContextPreview\":\""
                                + esc(oneLinePreview(extraSystemPrompt, 180))
                                + "\",\"outLen\":" + built.length + "}");
                // #endregion
                LOG.info("[H2Proxy] Body: RunSSE->UnifiedChat from cached Bidi prompt, len="
                        + cachedPrompt.length());
                return built;
            }
            ByteBuf rewritten = RunSseToUnifiedChatBodyConverter.maybeRewriteBodyForUnifiedChat(
                    Unpooled.wrappedBuffer(request.body), request.normalizedPath, request.headers);
            byte[] out = copyByteBuf(rewritten);
            if (out.length > 0 && !Arrays.equals(out, request.body)) {
                // #region agent log
                dbg(runId, "H2",
                        "CursorHttp2StreamAbortIntercept.buildUpstreamBody",
                        "bridge_body_output_converter",
                        "{\"finalModel\":\"" + esc(inferModelNameFromUnifiedBodyOrDefault(out))
                                + "\",\"promptSource\":\"run_sse_converter"
                                + "\",\"outLen\":" + out.length + "}");
                // #endregion
                LOG.info("[H2Proxy] Body: RunSSE->UnifiedChat fallback " + request.body.length
                        + "->" + out.length + " bytes");
                return out;
            }
            String textGuess = extractLongestUtf8Guess(request.body);
            if (textGuess != null && !textGuess.trim().isEmpty()) {
                byte[] built = CursorConnectUpstreamCodec.buildFramedUnifiedChatBody(
                        CursorConnectUpstreamCodec.DEFAULT_MODEL, textGuess.trim());
                // #region agent log
                dbg(runId, "H2",
                        "CursorHttp2StreamAbortIntercept.buildUpstreamBody",
                        "bridge_body_output_raw_guess",
                        "{\"finalModel\":\"" + esc(CursorConnectUpstreamCodec.DEFAULT_MODEL)
                                + "\",\"promptSource\":\"raw_utf8_guess"
                                + "\",\"promptPreview\":\"" + esc(oneLinePreview(textGuess, 120))
                                + "\",\"outLen\":" + built.length + "}");
                // #endregion
                LOG.info("[H2Proxy] Body: built UnifiedChat from raw RunSSE utf8 guess len="
                        + textGuess.trim().length());
                return built;
            }
            throw new IllegalStateException("Cannot bridge RunSSE body to UnifiedChat");
        } catch (Exception e) {
            if (!isExpectedMissingBidiPrompt(e)) {
                LOG.log(Level.WARNING, "[H2Proxy] RunSSE bridge body conversion failed", e);
            }
            throw new IllegalStateException("RunSSE bridge body conversion failed: " + e.getMessage(), e);
        }
    }

    private String inferModelNameFromUnifiedBodyOrDefault(byte[] unifiedBody) {
        byte[] payload = ConnectProtoUtil.extractPayloadFromWire(unifiedBody);
        if (payload == null || payload.length == 0) {
            return CursorConnectUpstreamCodec.DEFAULT_MODEL;
        }
        String model = findLikelyModel(payload);
        return model != null ? model : CursorConnectUpstreamCodec.DEFAULT_MODEL;
    }

    private static String chooseBridgedModel(String sessionModel,
                                             AgentRunSseModelResolver.ModelResolution resolution) {
        if (sessionModel != null && !sessionModel.trim().isEmpty()) {
            return sessionModel.trim();
        }
        if (resolution != null && resolution.model != null) {
            String model = resolution.model.trim();
            if (!model.isEmpty() && !"default".equalsIgnoreCase(model)) {
                return model;
            }
        }
        return CursorConnectUpstreamCodec.DEFAULT_MODEL;
    }

    private static String findLikelyModel(byte[] protobuf) {
        Candidate best = new Candidate();
        collectUtf8Candidates(protobuf, 0, 6, best, true);
        return best.value;
    }

    private String findCachedPrompt(DownstreamRequest request) {
        String requestId = extractRequestIdFromRunSseBody(request.body);
        if (requestId != null) {
            String cached = REQUEST_PROMPT_CACHE.get(requestId);
            if (cached != null && !cached.trim().isEmpty()) {
                return cached;
            }
        }
        String sessionId = headerFirst(request.headers, "x-session-id");
        if (sessionId != null) {
            String cached = SESSION_PROMPT_CACHE.get(sessionId);
            if (cached != null && !cached.trim().isEmpty()) {
                return cached;
            }
        }
        return null;
    }

    private String findCachedRulesContext(DownstreamRequest request) {
        String requestId = extractRequestIdFromRunSseBody(request.body);
        if (requestId != null) {
            String cached = REQUEST_RULES_CACHE.get(requestId);
            if (cached != null && !cached.trim().isEmpty()) {
                return cached;
            }
        }
        String sessionId = headerFirst(request.headers, "x-session-id");
        if (sessionId != null) {
            String cached = SESSION_RULES_CACHE.get(sessionId);
            if (cached != null && !cached.trim().isEmpty()) {
                return cached;
            }
        }
        return null;
    }

    private void cacheBidiContext(FullHttpRequest request, HttpProxyInterceptPipeline pipeline) {
        byte[] body = extractBody(request);
        String normalizedPath = normalizePath(request.uri());
        try {
            CursorSessionModelCache.maybeIngestFromBidiBody(
                    request.headers(), normalizedPath, Unpooled.wrappedBuffer(body));
        } catch (Exception e) {
            LOG.log(Level.FINE, "[H2Proxy] Cache Bidi model failed", e);
        }
        String sessionId = headerFirst(request.headers(), "x-session-id");
        if (sessionId == null && pipeline.getRequestProto() != null) {
            sessionId = pipeline.getRequestProto().getHost();
        }
        byte[] payload = decodeBidiOuterBody(body);
        String outerRequestId = extractRequestIdFromDecodedBidiPayload(payload);
        Long appendSeqNo = extractVarintField(payload, 3);
        String hexData = extractStringField(payload, 1);
        byte[] agentClientMsg = decodeHex(hexData);
        String topMessage = null;
        String structuredModel = null;
        String structuredText = null;
        String structuredRichText = null;
        String rulesContext = null;
        if (agentClientMsg != null && agentClientMsg.length > 0) {
            byte[] runRequest = extractMessageField(agentClientMsg, 1);
            byte[] conversationAction = extractMessageField(agentClientMsg, 4);
            byte[] action = null;
            byte[] conversationState = null;
            byte[] requestContext = null;
            byte[] requestEnv = null;
            byte[] selectedContext = null;
            byte[] invocationContext = null;
            byte[] ideState = null;
            byte[] skillOptions = null;
            String rulePathsPreview = null;
            String workspacePathsPreview = null;
            String requestContextToolPreview = null;
            String repositoryInfoPreview = null;
            String projectLayoutsPreview = null;
            String fileContentsPreview = null;
            String selectedFilesPreview = null;
            String visibleFilesPreview = null;
            int prependUserMessagesCount = 0;
            int requestContextRulesCount = 0;
            int workspacePathsCount = 0;
            int requestContextToolCount = 0;
            int repositoryInfoCount = 0;
            int projectLayoutsCount = 0;
            int fileContentsCount = 0;
            int selectedCursorRulesCount = 0;
            int selectedFilesCount = 0;
            int extraContextCount = 0;
            int visibleFilesCount = 0;
            int recentlyViewedFilesCount = 0;
            int rootPromptMessagesCount = 0;
            int turnCount = 0;
            int skillDescriptorsCount = 0;
            int customSystemPromptLen = 0;
            if (runRequest != null) {
                topMessage = "run_request";
                action = extractMessageField(runRequest, 2);
                byte[] modelDetails = extractMessageField(runRequest, 3);
                byte[] requestedModel = extractMessageField(runRequest, 9);
                structuredModel = firstNonBlank(
                        extractStringField(requestedModel, 1),
                        extractStringField(modelDetails, 1),
                        extractStringField(modelDetails, 3));
                conversationState = extractMessageField(runRequest, 1);
                String customSystemPrompt = extractStringField(runRequest, 8);
                customSystemPromptLen = customSystemPrompt == null ? 0 : customSystemPrompt.length();
                rootPromptMessagesCount = countLengthDelimitedField(conversationState, 1);
                turnCount = countLengthDelimitedField(conversationState, 8);
            } else if (conversationAction != null) {
                topMessage = "conversation_action";
                action = conversationAction;
            } else {
                topMessage = "other";
            }
            byte[] userMessageAction = extractMessageField(action, 1);
            byte[] userMessage = extractMessageField(userMessageAction, 1);
            structuredText = extractStringField(userMessage, 1);
            structuredRichText = extractStringField(userMessage, 8);
            requestContext = extractMessageField(userMessageAction, 2);
            prependUserMessagesCount = countLengthDelimitedField(userMessageAction, 4);
            selectedContext = extractMessageField(userMessage, 3);
            requestContextRulesCount = countLengthDelimitedField(requestContext, 2);
            rulePathsPreview = extractRulePathsPreview(requestContext, 20);
            requestEnv = extractMessageField(requestContext, 4);
            workspacePathsCount = countLengthDelimitedField(requestEnv, 2);
            workspacePathsPreview = extractRepeatedStringFieldPreview(requestEnv, 2, 4);
            requestContextToolCount = countLengthDelimitedField(requestContext, 7);
            requestContextToolPreview = extractMcpToolNamesPreview(requestContext, 5);
            repositoryInfoCount = countLengthDelimitedField(requestContext, 6);
            repositoryInfoPreview = extractRepositoryInfoPreview(requestContext, 4);
            projectLayoutsCount = countLengthDelimitedField(requestContext, 13);
            projectLayoutsPreview = extractProjectLayoutPreview(requestContext, 3);
            fileContentsCount = countLengthDelimitedField(requestContext, 20);
            fileContentsPreview = extractMapKeyPreview(requestContext, 20, 4);
            skillOptions = extractMessageField(requestContext, 18);
            skillDescriptorsCount = countLengthDelimitedField(skillOptions, 1);
            selectedCursorRulesCount = countLengthDelimitedField(selectedContext, 10);
            selectedFilesCount = countLengthDelimitedField(selectedContext, 4);
            selectedFilesPreview = extractSelectedFilePathsPreview(selectedContext, 5);
            extraContextCount = countLengthDelimitedField(selectedContext, 3);
            invocationContext = extractMessageField(selectedContext, 2);
            ideState = extractMessageField(invocationContext, 3);
            visibleFilesCount = countLengthDelimitedField(ideState, 1);
            recentlyViewedFilesCount = countLengthDelimitedField(ideState, 2);
            visibleFilesPreview = extractIdeStateFilesPreview(ideState, 1, 5);
            rulesContext = extractRulesContext(requestContext);
            // #region agent log
            dbg(debugRunId(request.headers(), outerRequestId), "H6",
                    "CursorHttp2StreamAbortIntercept.cacheBidiContext",
                    "bidi_context_probe",
                    "{\"topMessage\":\"" + esc(topMessage)
                            + "\",\"rootPromptMessagesCount\":" + rootPromptMessagesCount
                            + ",\"turnCount\":" + turnCount
                            + ",\"customSystemPromptLen\":" + customSystemPromptLen
                            + ",\"prependUserMessagesCount\":" + prependUserMessagesCount
                            + ",\"requestContextRulesCount\":" + requestContextRulesCount
                            + ",\"rulePathsPreview\":\"" + esc(rulePathsPreview)
                            + "\""
                            + ",\"skillDescriptorsCount\":" + skillDescriptorsCount
                            + ",\"selectedCursorRulesCount\":" + selectedCursorRulesCount
                            + ",\"selectedFilesCount\":" + selectedFilesCount
                            + ",\"extraContextCount\":" + extraContextCount
                            + ",\"rulesContextLen\":" + (rulesContext == null ? 0 : rulesContext.length()) + "}");
            // #endregion
            // #region agent log
            dbg(debugRunId(request.headers(), outerRequestId), "H_CTX",
                    "CursorHttp2StreamAbortIntercept.cacheBidiContext",
                    "bidi_context_deep_probe",
                    "{\"workspacePathsCount\":" + workspacePathsCount
                            + ",\"workspacePathsPreview\":\"" + esc(workspacePathsPreview)
                            + "\",\"requestContextToolCount\":" + requestContextToolCount
                            + ",\"requestContextToolPreview\":\"" + esc(requestContextToolPreview)
                            + "\",\"repositoryInfoCount\":" + repositoryInfoCount
                            + ",\"repositoryInfoPreview\":\"" + esc(repositoryInfoPreview)
                            + "\",\"projectLayoutsCount\":" + projectLayoutsCount
                            + ",\"projectLayoutsPreview\":\"" + esc(projectLayoutsPreview)
                            + "\",\"fileContentsCount\":" + fileContentsCount
                            + ",\"fileContentsPreview\":\"" + esc(fileContentsPreview)
                            + "\",\"selectedFilesPreview\":\"" + esc(selectedFilesPreview)
                            + "\",\"visibleFilesCount\":" + visibleFilesCount
                            + ",\"recentlyViewedFilesCount\":" + recentlyViewedFilesCount
                            + ",\"visibleFilesPreview\":\"" + esc(visibleFilesPreview) + "\"}");
            // #endregion
        }
        if (sessionId != null && !sessionId.isEmpty()
                && structuredModel != null && !structuredModel.isEmpty()) {
            CursorSessionModelCache.put(sessionId, structuredModel);
        }
        // #region agent log
        dbg(debugRunId(request.headers(), outerRequestId), "H5",
                "CursorHttp2StreamAbortIntercept.cacheBidiContext",
                "bidi_structured_probe",
                "{\"outerRequestId\":\"" + esc(outerRequestId)
                        + "\",\"appendSeqNo\":" + (appendSeqNo == null ? "null" : appendSeqNo.toString())
                        + ",\"topMessage\":\"" + esc(topMessage)
                        + "\",\"structuredText\":\"" + esc(oneLinePreview(structuredText, 120))
                        + "\",\"structuredRichText\":\"" + esc(oneLinePreview(structuredRichText, 120))
                        + "\",\"structuredRichTextPlain\":\""
                        + esc(oneLinePreview(extractTextFromRichTextJson(structuredRichText), 120))
                        + "\",\"structuredModel\":\"" + esc(structuredModel)
                        + "\",\"sessionId\":\"" + esc(sessionId)
                        + "\",\"sessionCacheModel\":\""
                        + esc(CursorSessionModelCache.getIfPresent(request.headers()))
                        + "\",\"agentUtf8Guess\":\"" + esc(oneLinePreview(extractLongestUtf8Guess(agentClientMsg), 120))
                        + "\"}");
        // #endregion
        String prompt = extractPromptFromBidiBody(body);
        if (prompt == null || prompt.trim().isEmpty()) {
            return;
        }
        if (sessionId != null && !sessionId.isEmpty()) {
            SESSION_PROMPT_CACHE.put(sessionId, prompt);
        }
        String requestId = outerRequestId;
        if (requestId != null && !requestId.isEmpty()) {
            REQUEST_PROMPT_CACHE.put(requestId, prompt);
        }
        if (rulesContext != null && !rulesContext.trim().isEmpty()) {
            if (sessionId != null && !sessionId.isEmpty()) {
                SESSION_RULES_CACHE.put(sessionId, rulesContext);
            }
            if (requestId != null && !requestId.isEmpty()) {
                REQUEST_RULES_CACHE.put(requestId, rulesContext);
            }
        }
        // #region agent log
        dbg(debugRunId(request.headers(), requestId), "H1",
                "CursorHttp2StreamAbortIntercept.cacheBidiContext",
                "bidi_cache_snapshot",
                "{\"requestId\":\"" + esc(requestId)
                        + "\",\"sessionId\":\"" + esc(sessionId)
                        + "\",\"promptLen\":" + prompt.length()
                        + ",\"promptPreview\":\"" + esc(oneLinePreview(prompt, 120))
                        + "\",\"promptLooksUuid\":" + looksLikeUuid(prompt)
                        + ",\"rulesContextLen\":" + (rulesContext == null ? 0 : rulesContext.length())
                        + ",\"sessionCacheModel\":\""
                        + esc(CursorSessionModelCache.getIfPresent(request.headers())) + "\"}");
        // #endregion
        LOG.info("[H2Proxy] Cached Bidi prompt len=" + prompt.length()
                + (requestId != null ? ", requestId=" + trunc(requestId, 36) : "")
                + (sessionId != null ? ", session=" + trunc(sessionId, 16) : ""));
    }

    private static String extractRequestIdFromRunSseBody(byte[] body) {
        byte[] payload = ConnectProtoUtil.extractPayloadFromWire(body);
        if (payload == null || payload.length == 0) {
            return null;
        }
        return extractStringField(payload, 1);
    }

    private static String extractRequestIdFromBidiBody(byte[] body) {
        return extractRequestIdFromDecodedBidiPayload(decodeBidiOuterBody(body));
    }

    private static String extractRequestIdFromDecodedBidiPayload(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }
        byte[] requestIdMsg = extractMessageField(payload, 2);
        return extractStringField(requestIdMsg, 1);
    }

    private static byte[] decodeBidiOuterBody(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        byte[] raw = body;
        if (raw.length >= 2 && (raw[0] & 0xFF) == 0x1f && (raw[1] & 0xFF) == 0x8b) {
            byte[] dec = ConnectProtoUtil.gzipDecompress(raw);
            if (dec != null && dec.length > 0) {
                raw = dec;
            }
        }
        return raw;
    }

    private static String extractPromptFromBidiBody(byte[] body) {
        byte[] payload = decodeBidiOuterBody(body);
        if (payload == null || payload.length == 0) {
            return null;
        }
        String hex = extractStringField(payload, 1);
        if (hex == null || hex.isEmpty()) {
            return null;
        }
        byte[] inner = decodeHex(hex);
        if (inner == null || inner.length == 0) {
            return null;
        }
        byte[] runRequest = extractMessageField(inner, 1);
        byte[] conversationAction = extractMessageField(inner, 4);
        byte[] action = runRequest != null ? extractMessageField(runRequest, 2) : conversationAction;
        byte[] userMessageAction = extractMessageField(action, 1);
        byte[] userMessage = extractMessageField(userMessageAction, 1);
        String text = extractStringField(userMessage, 1);
        if (text != null && !text.trim().isEmpty()) {
            return text.trim();
        }
        String richText = extractStringField(userMessage, 8);
        String prompt = extractTextFromRichTextJson(richText);
        if (prompt != null && !prompt.trim().isEmpty()) {
            return prompt.trim();
        }
        richText = findRichTextPayload(inner);
        prompt = extractTextFromRichTextJson(richText);
        if (prompt != null && !prompt.trim().isEmpty()) {
            return prompt.trim();
        }
        Candidate best = new Candidate();
        collectUtf8Candidates(inner, 0, 6, best, false);
        return best.value == null ? null : best.value.trim();
    }

    private static String extractRulesContext(byte[] requestContext) {
        if (requestContext == null || requestContext.length == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (byte[] ruleMsg : extractRepeatedMessageFields(requestContext, 2)) {
            String path = extractStringField(ruleMsg, 1);
            String content = extractStringField(ruleMsg, 2);
            if (content == null || content.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append("\n\n");
            }
            sb.append("Cursor rule");
            if (path != null && !path.trim().isEmpty()) {
                sb.append(" (").append(path.trim()).append(')');
            }
            sb.append(":\n").append(content.trim());
        }
        String cloudRule = extractStringField(requestContext, 16);
        if (cloudRule != null && !cloudRule.trim().isEmpty()) {
            if (sb.length() > 0) {
                sb.append("\n\n");
            }
            sb.append("Cloud rule:\n").append(cloudRule.trim());
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String extractRulePathsPreview(byte[] requestContext, int limit) {
        if (requestContext == null || requestContext.length == 0 || limit <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (byte[] ruleMsg : extractRepeatedMessageFields(requestContext, 2)) {
            String path = extractStringField(ruleMsg, 1);
            if (path == null || path.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(path.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String extractRepeatedStringFieldPreview(byte[] protobuf, int fieldNumber, int limit) {
        if (protobuf == null || protobuf.length == 0 || limit <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (String value : extractRepeatedStringFields(protobuf, fieldNumber)) {
            if (value == null || value.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(value.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String extractMcpToolNamesPreview(byte[] requestContext, int limit) {
        if (requestContext == null || requestContext.length == 0 || limit <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (byte[] toolMsg : extractRepeatedMessageFields(requestContext, 7)) {
            String name = firstNonBlank(
                    extractStringField(toolMsg, 1),
                    extractStringField(toolMsg, 5),
                    extractStringField(toolMsg, 2));
            if (name == null || name.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(name.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String extractRepositoryInfoPreview(byte[] requestContext, int limit) {
        if (requestContext == null || requestContext.length == 0 || limit <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (byte[] repoMsg : extractRepeatedMessageFields(requestContext, 6)) {
            String value = firstNonBlank(
                    extractStringField(repoMsg, 1),
                    extractStringField(repoMsg, 9),
                    extractStringField(repoMsg, 4));
            if (value == null || value.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(value.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String extractProjectLayoutPreview(byte[] requestContext, int limit) {
        if (requestContext == null || requestContext.length == 0 || limit <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (byte[] layoutMsg : extractRepeatedMessageFields(requestContext, 13)) {
            String path = extractStringField(layoutMsg, 1);
            if (path == null || path.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(path.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String extractMapKeyPreview(byte[] protobuf, int fieldNumber, int limit) {
        if (protobuf == null || protobuf.length == 0 || limit <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (byte[] entryMsg : extractRepeatedMessageFields(protobuf, fieldNumber)) {
            String key = extractStringField(entryMsg, 1);
            if (key == null || key.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(key.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String extractSelectedFilePathsPreview(byte[] selectedContext, int limit) {
        if (selectedContext == null || selectedContext.length == 0 || limit <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (byte[] fileMsg : extractRepeatedMessageFields(selectedContext, 4)) {
            String path = firstNonBlank(extractStringField(fileMsg, 3), extractStringField(fileMsg, 2));
            if (path == null || path.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(path.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String extractIdeStateFilesPreview(byte[] ideState, int fieldNumber, int limit) {
        if (ideState == null || ideState.length == 0 || limit <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (byte[] fileMsg : extractRepeatedMessageFields(ideState, fieldNumber)) {
            String path = firstNonBlank(extractStringField(fileMsg, 2), extractStringField(fileMsg, 1));
            if (path == null || path.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(path.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String findRichTextPayload(byte[] protobuf) {
        Candidate best = new Candidate();
        collectRichTextCandidates(protobuf, 0, 6, best);
        return best.value;
    }

    private static String extractTextFromRichTextJson(String richTextJson) {
        if (richTextJson == null || richTextJson.isEmpty()) {
            return null;
        }
        Matcher matcher = RICHTEXT_TEXT_PATTERN.matcher(richTextJson);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String piece = jsonUnescape(matcher.group(1));
            if (piece == null || piece.trim().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(piece);
        }
        String result = sb.toString().trim();
        return result.isEmpty() ? null : result;
    }

    private static String jsonUnescape(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                out.append(c);
                continue;
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
                            break;
                        } catch (NumberFormatException ignored) {
                        }
                    }
                    out.append(n);
                    break;
                default:
                    out.append(n);
                    break;
            }
        }
        return out.toString();
    }

    private static String extractStringField(byte[] protobuf, int wantedField) {
        if (protobuf == null || protobuf.length == 0) {
            return null;
        }
        int pos = 0;
        while (pos < protobuf.length) {
            int[] tag = readTag(protobuf, pos);
            if (tag == null) {
                return null;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 2) {
                int[] len = readVarint(protobuf, pos);
                if (len == null) {
                    return null;
                }
                int size = len[0];
                pos = len[1];
                if (size < 0 || pos + size > protobuf.length) {
                    return null;
                }
                if (fieldNumber == wantedField) {
                    return safeUtf8(protobuf, pos, size);
                }
                pos += size;
            } else {
                pos = skipField(protobuf, pos, wireType);
                if (pos < 0) {
                    return null;
                }
            }
        }
        return null;
    }

    private static List<String> extractRepeatedStringFields(byte[] protobuf, int wantedField) {
        List<String> out = new ArrayList<>();
        if (protobuf == null || protobuf.length == 0) {
            return out;
        }
        int pos = 0;
        while (pos < protobuf.length) {
            int[] tag = readTag(protobuf, pos);
            if (tag == null) {
                return out;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 2) {
                int[] len = readVarint(protobuf, pos);
                if (len == null) {
                    return out;
                }
                int size = len[0];
                pos = len[1];
                if (size < 0 || pos + size > protobuf.length) {
                    return out;
                }
                if (fieldNumber == wantedField) {
                    String value = safeUtf8(protobuf, pos, size);
                    if (value != null) {
                        out.add(value);
                    }
                }
                pos += size;
            } else {
                pos = skipField(protobuf, pos, wireType);
                if (pos < 0) {
                    return out;
                }
            }
        }
        return out;
    }

    private static byte[] extractMessageField(byte[] protobuf, int wantedField) {
        if (protobuf == null || protobuf.length == 0) {
            return null;
        }
        int pos = 0;
        while (pos < protobuf.length) {
            int[] tag = readTag(protobuf, pos);
            if (tag == null) {
                return null;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 2) {
                int[] len = readVarint(protobuf, pos);
                if (len == null) {
                    return null;
                }
                int size = len[0];
                pos = len[1];
                if (size < 0 || pos + size > protobuf.length) {
                    return null;
                }
                if (fieldNumber == wantedField) {
                    return Arrays.copyOfRange(protobuf, pos, pos + size);
                }
                pos += size;
            } else {
                pos = skipField(protobuf, pos, wireType);
                if (pos < 0) {
                    return null;
                }
            }
        }
        return null;
    }

    private static byte[][] extractRepeatedMessageFields(byte[] protobuf, int wantedField) {
        if (protobuf == null || protobuf.length == 0) {
            return new byte[0][];
        }
        java.util.ArrayList<byte[]> result = new java.util.ArrayList<byte[]>();
        int pos = 0;
        while (pos < protobuf.length) {
            int[] tag = readTag(protobuf, pos);
            if (tag == null) {
                break;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 2) {
                int[] len = readVarint(protobuf, pos);
                if (len == null) {
                    break;
                }
                int size = len[0];
                pos = len[1];
                if (size < 0 || pos + size > protobuf.length) {
                    break;
                }
                if (fieldNumber == wantedField) {
                    result.add(Arrays.copyOfRange(protobuf, pos, pos + size));
                }
                pos += size;
            } else {
                pos = skipField(protobuf, pos, wireType);
                if (pos < 0) {
                    break;
                }
            }
        }
        return result.toArray(new byte[result.size()][]);
    }

    private static Long extractVarintField(byte[] protobuf, int wantedField) {
        if (protobuf == null || protobuf.length == 0) {
            return null;
        }
        int pos = 0;
        while (pos < protobuf.length) {
            int[] tag = readTag(protobuf, pos);
            if (tag == null) {
                return null;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 0) {
                int[] val = readVarint(protobuf, pos);
                if (val == null) {
                    return null;
                }
                if (fieldNumber == wantedField) {
                    return (long) val[0];
                }
                pos = val[1];
            } else if (wireType == 2) {
                int[] len = readVarint(protobuf, pos);
                if (len == null) {
                    return null;
                }
                int size = len[0];
                pos = len[1] + size;
                if (size < 0 || pos > protobuf.length) {
                    return null;
                }
            } else {
                pos = skipField(protobuf, pos, wireType);
                if (pos < 0) {
                    return null;
                }
            }
        }
        return null;
    }

    private static String extractNestedFirstStringField(byte[] protobuf, int wantedField) {
        if (protobuf == null || protobuf.length == 0) {
            return null;
        }
        int pos = 0;
        while (pos < protobuf.length) {
            int[] tag = readTag(protobuf, pos);
            if (tag == null) {
                return null;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 2) {
                int[] len = readVarint(protobuf, pos);
                if (len == null) {
                    return null;
                }
                int size = len[0];
                pos = len[1];
                if (size < 0 || pos + size > protobuf.length) {
                    return null;
                }
                if (fieldNumber == wantedField) {
                    return extractStringField(Arrays.copyOfRange(protobuf, pos, pos + size), 1);
                }
                pos += size;
            } else {
                pos = skipField(protobuf, pos, wireType);
                if (pos < 0) {
                    return null;
                }
            }
        }
        return null;
    }

    private static byte[] decodeHex(String hex) {
        if (hex == null) {
            return null;
        }
        String raw = hex.trim();
        if ((raw.length() & 1) != 0) {
            return null;
        }
        byte[] out = new byte[raw.length() / 2];
        for (int i = 0; i < raw.length(); i += 2) {
            int hi = Character.digit(raw.charAt(i), 16);
            int lo = Character.digit(raw.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static void collectRichTextCandidates(byte[] data, int depth, int maxDepth, Candidate best) {
        if (data == null || data.length == 0 || depth > maxDepth) {
            return;
        }
        int pos = 0;
        while (pos < data.length) {
            int[] tag = readTag(data, pos);
            if (tag == null) {
                return;
            }
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 2) {
                int[] len = readVarint(data, pos);
                if (len == null) {
                    return;
                }
                int size = len[0];
                pos = len[1];
                if (size < 0 || pos + size > data.length) {
                    return;
                }
                byte[] chunk = Arrays.copyOfRange(data, pos, pos + size);
                String s = safeUtf8(chunk, 0, chunk.length);
                if (s != null && s.contains("\"root\"") && s.contains("\"children\"")
                        && s.contains("\"text\"")) {
                    int score = 200 + s.length();
                    if (score > best.score) {
                        best.value = s;
                        best.score = score;
                    }
                }
                collectRichTextCandidates(chunk, depth + 1, maxDepth, best);
                pos += size;
            } else {
                pos = skipField(data, pos, wireType);
                if (pos < 0) {
                    return;
                }
            }
        }
    }

    private static void collectUtf8Candidates(byte[] data, int depth, int maxDepth,
                                              Candidate best, boolean modelMode) {
        if (data == null || data.length == 0 || depth > maxDepth) {
            return;
        }
        int pos = 0;
        while (pos < data.length) {
            int[] tag = readTag(data, pos);
            if (tag == null) {
                return;
            }
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 2) {
                int[] len = readVarint(data, pos);
                if (len == null) {
                    return;
                }
                int size = len[0];
                pos = len[1];
                if (size < 0 || pos + size > data.length) {
                    return;
                }
                byte[] chunk = Arrays.copyOfRange(data, pos, pos + size);
                String s = safeUtf8(chunk, 0, chunk.length);
                if (s != null) {
                    int score = modelMode ? scoreModelCandidate(s) : scorePromptCandidate(s);
                    if (score > best.score) {
                        best.value = s;
                        best.score = score;
                    }
                }
                collectUtf8Candidates(chunk, depth + 1, maxDepth, best, modelMode);
                pos += size;
            } else {
                pos = skipField(data, pos, wireType);
                if (pos < 0) {
                    return;
                }
            }
        }
    }

    private static int scoreModelCandidate(String text) {
        String t = text == null ? "" : text.trim();
        if (t.length() < 3 || t.length() > 120) {
            return 0;
        }
        String low = t.toLowerCase(Locale.ROOT);
        if (low.contains("claude") || low.contains("gpt")
                || low.contains("gemini") || low.contains("grok")
                || low.contains("deepseek")) {
            return 100 + t.length();
        }
        return 0;
    }

    private static int scorePromptCandidate(String text) {
        String t = text == null ? "" : text.trim();
        if (t.length() < 2 || t.length() > 4000) {
            return 0;
        }
        if (looksLikeUuid(t) || looksLikeHexBlob(t) || looksLikePath(t)) {
            return 0;
        }
        int score = Math.min(80, t.length() / 6);
        if (containsCjk(t)) {
            score += 80;
        }
        if (t.indexOf(' ') >= 0) {
            score += 20;
        }
        if (t.indexOf('\n') >= 0) {
            score += 10;
        }
        if (t.startsWith("{") && t.endsWith("}")) {
            score -= 30;
        }
        if (t.contains("<user_query>")) {
            score += 120;
        }
        if (t.length() > 2048) {
            score -= 40;
        }
        return score;
    }

    private static boolean looksLikeUuid(String t) {
        return t.matches("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    }

    private static boolean looksLikeHexBlob(String t) {
        return t.length() >= 32 && t.matches("(?i)^[0-9a-f]+$");
    }

    private static boolean looksLikePath(String t) {
        int slash = 0;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '\\' || c == '/') {
                slash++;
            }
        }
        return slash >= 3;
    }

    private static boolean containsCjk(String t) {
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c >= 0x4E00 && c <= 0x9FFF) {
                return true;
            }
        }
        return false;
    }

    private static String safeUtf8(byte[] data, int off, int len) {
        if (data == null || len <= 0 || off < 0 || off + len > data.length) {
            return null;
        }
        String s = new String(data, off, len, StandardCharsets.UTF_8);
        return s.indexOf('\uFFFD') >= 0 ? null : s;
    }

    private static int[] readTag(byte[] data, int pos) {
        int[] varint = readVarint(data, pos);
        if (varint == null) {
            return null;
        }
        int tag = varint[0];
        return new int[] {tag >>> 3, tag & 0x07, varint[1]};
    }

    private static int[] readVarint(byte[] data, int pos) {
        int result = 0;
        int shift = 0;
        while (pos < data.length && shift < 35) {
            int b = data[pos++] & 0xFF;
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return new int[] {result, pos};
            }
            shift += 7;
        }
        return null;
    }

    private static int skipField(byte[] data, int pos, int wireType) {
        switch (wireType) {
            case 0:
                int[] varint = readVarint(data, pos);
                return varint == null ? -1 : varint[1];
            case 1:
                return pos + 8 <= data.length ? pos + 8 : -1;
            case 2:
                int[] len = readVarint(data, pos);
                if (len == null) {
                    return -1;
                }
                int size = len[0];
                int end = len[1] + size;
                return size >= 0 && end <= data.length ? end : -1;
            case 5:
                return pos + 4 <= data.length ? pos + 4 : -1;
            default:
                return -1;
        }
    }

    private static byte[] copyByteBuf(ByteBuf buf) {
        byte[] out = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), out);
        return out;
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

    private static byte[] utf8(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] encodeLengthDelimitedField(int fieldNumber, byte[] payload) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(payload.length + 8);
        writeVarint(out, (fieldNumber << 3) | 2);
        writeVarint(out, payload.length);
        out.write(payload);
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

    private static String headerFirst(HttpHeaders headers, String name) {
        String value = headers.get(name);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        for (String headerName : headers.names()) {
            if (headerName != null && headerName.equalsIgnoreCase(name)) {
                return headers.get(headerName);
            }
        }
        return null;
    }

    private static String extractLongestUtf8Guess(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        String s = new String(data, StandardCharsets.UTF_8);
        StringBuilder cur = new StringBuilder();
        String best = "";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t') {
                if (cur.length() > best.length()) {
                    best = cur.toString();
                }
                cur.setLength(0);
            } else if (c != '\uFFFD') {
                cur.append(c);
            }
        }
        if (cur.length() > best.length()) {
            best = cur.toString();
        }
        best = best.trim();
        return best.isEmpty() ? null : best;
    }

    private static String sanitizeAssistantText(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String cleaned = LEADING_CONNECT_UUID_PREFIX_PATTERN.matcher(text).replaceFirst("");
        cleaned = LEADING_CONTROL_GARBAGE_PATTERN.matcher(cleaned).replaceFirst("");
        if (!cleaned.equals(text)) {
            // #region agent log
            dbg("bridge-stream", "H4",
                    "CursorHttp2StreamAbortIntercept.sanitizeAssistantText",
                    "bridge_text_sanitized",
                    "{\"before\":\"" + esc(oneLinePreview(text, 120))
                            + "\",\"after\":\"" + esc(oneLinePreview(cleaned, 120)) + "\"}");
            // #endregion
        }
        return cleaned;
    }

    private static boolean isRequestIdOnlyRunSseBody(byte[] body) {
        byte[] payload = ConnectProtoUtil.extractPayloadFromWire(body);
        if (payload == null || payload.length == 0) {
            return false;
        }
        String requestId = extractRequestIdFromRunSseBody(body);
        if (requestId == null || requestId.isEmpty()) {
            return false;
        }
        String field1 = extractStringField(payload, 1);
        if (!requestId.equals(field1)) {
            return false;
        }
        return payload.length <= requestId.length() + 4;
    }

    public static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return null;
    }

    private static boolean isExpectedMissingBidiPrompt(Throwable t) {
        Throwable cur = t;
        while (cur != null) {
            String msg = cur.getMessage();
            if (msg != null && msg.contains("RunSSE body only carries requestId; missing BidiAppend prompt")) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }

    private static int countLengthDelimitedField(byte[] protobuf, int wantedField) {
        if (protobuf == null || protobuf.length == 0) {
            return 0;
        }
        int count = 0;
        int pos = 0;
        while (pos < protobuf.length) {
            int[] tag = readTag(protobuf, pos);
            if (tag == null) {
                return count;
            }
            int fieldNumber = tag[0];
            int wireType = tag[1];
            pos = tag[2];
            if (wireType == 2) {
                int[] len = readVarint(protobuf, pos);
                if (len == null) {
                    return count;
                }
                int size = len[0];
                pos = len[1];
                if (size < 0 || pos + size > protobuf.length) {
                    return count;
                }
                if (fieldNumber == wantedField) {
                    count++;
                }
                pos += size;
            } else {
                pos = skipField(protobuf, pos, wireType);
                if (pos < 0) {
                    return count;
                }
            }
        }
        return count;
    }

    // ================================================================
    //  pipeline / response 生命周期
    // ================================================================

    private void ensureFullRequestAggregation(Channel clientChannel,
                                              HttpProxyInterceptPipeline pipeline) {
        pipeline.resetBeforeHead();
        if (clientChannel.pipeline().get(AGGREGATOR_NAME) == null) {
            clientChannel.pipeline().addAfter("httpCodec", AGGREGATOR_NAME,
                    new HttpObjectAggregator(MAX_FULL_REQUEST_BYTES));
        }
    }

    private void removeAggregationHandlers(Channel clientChannel) {
        if (clientChannel.pipeline().get(AGGREGATOR_NAME) != null) {
            clientChannel.pipeline().remove(AGGREGATOR_NAME);
        }
    }

    private void finishChunkedResponse(Channel clientChannel, boolean keepAlive) {
        if (!clientChannel.isActive()) {
            completeCurrentResponse(clientChannel);
            return;
        }
        ChannelFuture future = clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);
        future.addListener(f -> finalizeResponse(clientChannel, keepAlive));
    }

    private void finishChunkedResponseTracked(Channel clientChannel, boolean keepAlive,
                                              String runId, String hypothesisId, String reason) {
        if (!clientChannel.isActive()) {
            // #region agent log
            dbg(runId, hypothesisId,
                    "CursorHttp2StreamAbortIntercept.finishChunkedResponseTracked",
                    "abort_http_last_chunk_skipped_inactive",
                    "{\"reason\":\"" + esc(reason) + "\"}");
            // #endregion
            completeCurrentResponse(clientChannel);
            return;
        }
        // #region agent log
        dbg(runId, hypothesisId,
                "CursorHttp2StreamAbortIntercept.finishChunkedResponseTracked",
                "abort_http_last_chunk_enqueued",
                "{\"reason\":\"" + esc(reason)
                        + "\",\"keepAlive\":" + keepAlive + "}");
        // #endregion
        ChannelFuture future = clientChannel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);
        future.addListener(f -> {
            // #region agent log
            dbg(runId, hypothesisId,
                    "CursorHttp2StreamAbortIntercept.finishChunkedResponseTracked",
                    "abort_http_last_chunk_flushed",
                    "{\"reason\":\"" + esc(reason)
                            + "\",\"success\":" + f.isSuccess()
                            + ",\"cause\":\""
                            + esc(f.cause() == null ? null : String.valueOf(f.cause()))
                            + "\"}");
            // #endregion
            finalizeResponse(clientChannel, keepAlive);
        });
    }

    private void writeAndFinalize(Channel clientChannel,
                                  FullHttpResponse response, boolean keepAlive) {
        if (!clientChannel.isActive()) {
            completeCurrentResponse(clientChannel);
            return;
        }
        clientChannel.writeAndFlush(response)
                .addListener(f -> finalizeResponse(clientChannel, keepAlive));
    }

    private void finalizeResponse(Channel clientChannel, boolean keepAlive) {
        completeCurrentResponse(clientChannel);
        if (!keepAlive && clientChannel.isActive()) {
            clientChannel.close();
        }
    }

    private void completeCurrentResponse(Channel clientChannel) {
        try {
            ClientResponseGate.forChannel(clientChannel).completeCurrentResponse();
        } catch (Exception ignored) {
        }
    }

    private void sendPlainAsync(Channel clientChannel,
                                HttpResponseStatus status,
                                String msg,
                                boolean keepAlive) {
        if (!clientChannel.isActive()) {
            completeCurrentResponse(clientChannel);
            return;
        }
        clientChannel.eventLoop().execute(() -> {
            FullHttpResponse resp = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1,
                    status,
                    Unpooled.copiedBuffer(msg, StandardCharsets.UTF_8));
            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
            resp.headers().set(HttpHeaderNames.CONTENT_LENGTH, resp.content().readableBytes());
            HttpUtil.setKeepAlive(resp, keepAlive);
            writeAndFinalize(clientChannel, resp, keepAlive);
        });
    }

    // ================================================================
    //  日志辅助
    // ================================================================

    private static void dl(String loc, String msg, String data) {
        try (FileWriter fw = new FileWriter(DEBUG_LOG_PATH, true)) {
            fw.write("{\"sessionId\":\"064e27\",\"location\":\"" + esc(loc)
                    + "\",\"message\":\"" + esc(msg)
                    + "\",\"data\":" + (data != null ? data : "null")
                    + ",\"timestamp\":" + System.currentTimeMillis() + "}\n");
        } catch (Exception ignored) {
        }
    }

    private static void dbg(String runId, String hypothesisId, String loc, String msg, String data) {
        try (FileWriter fw = new FileWriter(DEBUG_RUNTIME_LOG_PATH, true)) {
            fw.write("{\"sessionId\":\"" + DEBUG_RUNTIME_SESSION_ID
                    + "\",\"runId\":\"" + esc(runId)
                    + "\",\"hypothesisId\":\"" + esc(hypothesisId)
                    + "\",\"location\":\"" + esc(loc)
                    + "\",\"message\":\"" + esc(msg)
                    + "\",\"data\":" + (data != null ? data : "null")
                    + ",\"timestamp\":" + System.currentTimeMillis() + "}\n");
        } catch (Exception ignored) {
        }
    }

    private static String debugRunId(HttpHeaders headers, String bodyRequestId) {
        String requestId = headerFirst(headers, "x-request-id");
        if (requestId != null && !requestId.isEmpty()) {
            return requestId;
        }
        if (bodyRequestId != null && !bodyRequestId.isEmpty()) {
            return bodyRequestId;
        }
        String sessionId = headerFirst(headers, "x-session-id");
        return sessionId != null && !sessionId.isEmpty() ? sessionId : "no-id";
    }

    private static String oneLinePreview(String s, int max) {
        if (s == null) {
            return "";
        }
        return trunc(s.replace('\r', ' ').replace('\n', ' '), max);
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

    private static void printHeaders(String label, HttpHeaders headers) {
        StringBuilder sb = new StringBuilder(label).append(":\n");
        for (Map.Entry<String, String> e : headers) {
            String v = e.getValue();
            if (e.getKey().equalsIgnoreCase("Authorization")
                    && v != null && v.length() > 40) {
                v = v.substring(0, 40) + "...";
            }
            sb.append("  ").append(e.getKey()).append(": ").append(v).append('\n');
        }
        LOG.info(sb.toString());
    }

    private static void printOkHeaders(String label, Headers headers) {
        StringBuilder sb = new StringBuilder(label).append(":\n");
        for (int i = 0; i < headers.size(); i++) {
            String name = headers.name(i);
            String val = headers.value(i);
            if (name.equalsIgnoreCase("Authorization")
                    && val != null && val.length() > 40) {
                val = val.substring(0, 40) + "...";
            }
            sb.append("  ").append(name).append(": ").append(val).append('\n');
        }
        LOG.info(sb.toString());
    }

    private static String hexPrefix(byte[] data, int maxBytes) {
        if (data == null || data.length == 0) {
            return "";
        }
        int n = Math.min(maxBytes, data.length);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", data[i]));
        }
        if (data.length > maxBytes) {
            sb.append("...");
        }
        return sb.toString();
    }

    private static String trunc(String s, int max) {
        if (s == null) {
            return "null";
        }
        return s.length() <= max ? s : s.substring(0, max) + "...(" + s.length() + ")";
    }

    private static final class DownstreamRequest {
        final String method;
        final String normalizedPath;
        final String upstreamUrl;
        final HttpHeaders headers;
        final byte[] body;
        final boolean keepAlive;
        final boolean abortAware;
        final RouteKind routeKind;

        private DownstreamRequest(String method, String normalizedPath,
                                  String upstreamUrl, HttpHeaders headers,
                                  byte[] body, boolean keepAlive,
                                  boolean abortAware, RouteKind routeKind) {
            this.method = method;
            this.normalizedPath = normalizedPath;
            this.upstreamUrl = upstreamUrl;
            this.headers = headers;
            this.body = body;
            this.keepAlive = keepAlive;
            this.abortAware = abortAware;
            this.routeKind = routeKind;
        }
    }

    private static final class Candidate {
        String value;
        int score;
    }

    private enum RouteKind {
        PASSTHROUGH,
        CACHE_BIDI_PASSTHROUGH,
        BRIDGE_TO_UNIFIED_CHAT,
        PROXY_HTTP2_DIRECT
    }
}
