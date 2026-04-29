package com.github.monkeywie.proxyee.intercept.cursor;

import cn.hutool.core.util.StrUtil;
import com.github.monkeywie.proxyee.connect.ConnectProtoUtil;
import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.handler.codec.http.*;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Host 含 cursor.sh 时扫描响应体；命中 zmgnb666 则先转发当前分块再断上游。 */
public class CursorStreamAbortIntercept2 extends HttpProxyIntercept {

    private static final Logger LOG = Logger.getLogger(CursorStreamAbortIntercept2.class.getName());

    public static final String DEFAULT_ABORT_TOKEN = "zmgnb666";

    private static final AttributeKey<CursorAbortState> STATE =
            AttributeKey.valueOf("cursorStreamAbortState");
    private static final ConcurrentHashMap<String, SessionTaskState> SESSION_TASKS = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService HEARTBEAT_EXECUTOR =
            Executors.newScheduledThreadPool(1, r -> {
                Thread t = new Thread(r, "cursor-bidi-heartbeat");
                t.setDaemon(true);
                return t;
            });
    private static final Duration HEARTBEAT_INTERVAL = Duration.ofMillis(50);
    private static final Duration SESSION_IDLE_TTL = Duration.ofMinutes(20000);
    private static final int MAX_SEND_FAILS = 3;
    private static final Set<String> HEARTBEAT_HEADER_ALLOWLIST = new HashSet<>(Arrays.asList(
            "authorization",
            "connect-protocol-version",
            "content-type",
            "accept-encoding",
            "user-agent",
            "x-request-id",
            "x-session-id",
            "x-original-request-id",
            "x-client-key",
            "x-cursor-checksum",
            "x-cursor-client-version",
            "x-cursor-client-type",
            "x-cursor-client-os",
            "x-cursor-client-arch",
            "x-cursor-client-device-type",
            "x-cursor-streaming",
            "x-cursor-timezone",
            "x-cursor-retryinterceptor-enabled",
            "x-blob-encryption-key"));
    private static final Set<String> HOP_HEADERS = new HashSet<>(Arrays.asList(
            "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade",
            "proxy-authenticate", "proxy-authorization", "te", "trailers", "content-length"));
    private static final byte[] MIN_HEARTBEAT_BODY = new byte[]{0x0a, 0x00};

    private final String abortToken;

    public CursorStreamAbortIntercept2() {
        this(DEFAULT_ABORT_TOKEN);
    }

    public CursorStreamAbortIntercept2(String abortToken) {
        if (abortToken == null || abortToken.isEmpty()) {
            throw new IllegalArgumentException("abortToken");
        }
        this.abortToken = abortToken;
    }

    @Override
    public void beforeRequest(Channel clientChannel, HttpRequest httpRequest,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        String host = hostFrom(httpRequest);
        String uri = httpRequest.uri();
        String normalizedUri = normalizePathOnly(uri);
        boolean isRunSse = StrUtil.isNotBlank(normalizedUri) && normalizedUri.contains("agent.v1.AgentService/RunSSE");
        boolean isBidiAppend = StrUtil.isNotBlank(normalizedUri) && normalizedUri.contains("aiserver.v1.BidiService/BidiAppend");
        boolean watch = host != null
                && host.toLowerCase().contains("cursor.sh")
                && host.toLowerCase().contains("api")
                && (isRunSse || isBidiAppend);
        if (watch) {
            CursorAbortState st = new CursorAbortState();
            st.requestUri = uri;
            st.uriClass = isRunSse ? "RunSSE" : "BidiAppend";
            st.host = host;
            st.sessionId = headerFirstIgnoreCase(httpRequest.headers(), "x-session-id");
            st.abortNeedle = abortToken.getBytes(StandardCharsets.UTF_8);
            st.overlap = Math.max(0, st.abortNeedle.length - 1);
            clientChannel.attr(STATE).set(st);
            LOG.info(() -> String.format("[CursorAbort] monitor response for host=%s uri=%s session=%s",
                    host, uri, valueOrDash(st.sessionId)));
            if (isRunSse) {
                bootstrapSessionTask(st.sessionId);
            } else if (isBidiAppend) {
                captureBidiAppendHeaders(st.sessionId, host, httpRequest.headers());
            }
        } else {
            clientChannel.attr(STATE).remove();
        }
        pipeline.beforeRequest(clientChannel, httpRequest);
    }

    @Override
    public void beforeRequest(Channel clientChannel, HttpContent httpContent,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        CursorAbortState st = clientChannel.attr(STATE).get();
        if (st != null && "BidiAppend".equals(st.uriClass)) {
            ByteBuf content = httpContent.content();
            if (content.readableBytes() > 0) {
                byte[] bytes = new byte[content.readableBytes()];
                content.getBytes(content.readerIndex(), bytes);
                st.requestBodyBuffer.write(bytes);
            }
            if (httpContent instanceof LastHttpContent) {
                captureBidiAppendTemplate(st.sessionId, st.requestBodyBuffer.toByteArray());
            }
        }
        pipeline.beforeRequest(clientChannel, httpContent);
    }

    @Override
    public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        CursorAbortState st = clientChannel.attr(STATE).get();
        if (st == null || st.aborted) {
            pipeline.afterResponse(clientChannel, proxyChannel, httpResponse);
            return;
        }
        st.httpResponse = httpResponse;
        ensureGzipDecompressor(proxyChannel, httpResponse, st);
        pipeline.afterResponse(clientChannel, proxyChannel, httpResponse);
    }

    @Override
    public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        CursorAbortState st = clientChannel.attr(STATE).get();
        if (st == null) {
            pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
            return;
        }
        if (st.aborted) {
            ReferenceCountUtil.release(httpContent);
            return;
        }

        byte[] needle = st.abortNeedle;
        HttpResponse resp = pipeline.getHttpResponse();
        if (resp == null) {
            resp = st.httpResponse;
        }

        ByteBuf buf = httpContent.content();
        int n = buf.readableBytes();
        if (n == 0) {
            pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
            return;
        }

        byte[] chunk = new byte[n];
        buf.getBytes(buf.readerIndex(), chunk);
        final String uriForLog = st.requestUri != null ? st.requestUri : "";
        LOG.info(() -> String.format(
                "返回数据 token matched uri=%s, forwarding chunk then closing upstream (bytes=%d)",
                uriForLog, n));
        if (containsAbortPattern(st.tail, chunk, needle)) {
//            final String uriForLog = st.requestUri != null ? st.requestUri : "";
            LOG.info(() -> String.format(
                    "匹配到了[CursorAbort] token matched uri=%s, forwarding chunk then closing upstream (bytes=%d)",
                    uriForLog, n));
            pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
            st.aborted = true;
            finishAndClose(clientChannel, proxyChannel, resp, httpContent);
            return;
        }

        st.tail = suffixForOverlap(chunk, needle.length);
        pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
    }

    private void ensureGzipDecompressor(Channel proxyChannel, HttpResponse httpResponse, CursorAbortState st) {
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

    private void finishAndClose(Channel clientChannel, Channel proxyChannel,
                                HttpResponse httpResponse, HttpContent lastForwarded) {
        boolean needSyntheticLast = HttpUtil.isTransferEncodingChunked(httpResponse)
                && !(lastForwarded instanceof LastHttpContent);
        if (needSyntheticLast) {
            ChannelFuture f = clientChannel.writeAndFlush(new DefaultLastHttpContent());
            f.addListener(cf -> {
                LOG.info("[CursorAbort] synthetic LastHttpContent flushed, closing channels");
                safeClose(proxyChannel);
                safeClose(clientChannel);
            });
        } else {
            LOG.info("[CursorAbort] closing upstream (response already terminal chunk)");
            safeClose(proxyChannel);
            safeClose(clientChannel);
        }
    }

    private static void safeClose(Channel ch) {
        if (ch != null && ch.isActive()) {
            ch.close();
        }
    }

    static boolean containsAbortPattern(byte[] prevTail, byte[] chunk, byte[] needle) {
        return findAbortNeedleStartIndex(prevTail, chunk, needle) >= 0;
    }

    /**
     * 在 {@code prevTail + chunk} 拼接缓冲中查找 needle 首次出现的起始下标；未找到返回 -1。
     */
    static int findAbortNeedleStartIndex(byte[] prevTail, byte[] chunk, byte[] needle) {
        if (needle == null || needle.length == 0) {
            return -1;
        }
        int pl = prevTail == null ? 0 : prevTail.length;
        int cl = chunk == null ? 0 : chunk.length;
        byte[] hay = new byte[pl + cl];
        if (pl > 0) {
            System.arraycopy(prevTail, 0, hay, 0, pl);
        }
        if (cl > 0) {
            System.arraycopy(chunk, 0, hay, pl, cl);
        }
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    static byte[] suffixForOverlap(byte[] chunk, int needleLen) {
        int max = Math.max(0, needleLen - 1);
        if (chunk.length == 0 || max == 0) {
            return null;
        }
        int take = Math.min(max, chunk.length);
        byte[] tail = new byte[take];
        System.arraycopy(chunk, chunk.length - take, tail, 0, take);
        return tail;
    }

    static String hostFrom(HttpRequest req) {
        String host = req.headers().get(HttpHeaderNames.HOST);
        if (host != null) {
            int colon = host.indexOf(':');
            return colon < 0 ? host : host.substring(0, colon);
        }
        try {
            java.net.URI uri = java.net.URI.create(req.uri());
            return uri.getHost();
        } catch (Exception e) {
            LOG.log(Level.FINE, "hostFrom uri parse", e);
            return null;
        }
    }

    static final class CursorAbortState {
        String requestUri;
        String uriClass;
        String sessionId;
        String host;
        byte[] abortNeedle;
        int overlap;
        byte[] tail;
        boolean aborted;
        boolean decompressorAdded;
        HttpResponse httpResponse;
        final ByteArrayOutputStream requestBodyBuffer = new ByteArrayOutputStream(512);
    }

    static final class SessionTaskState {
        final String sessionId;
        volatile boolean taskStarted;
        volatile boolean readyToSend;
        volatile String host;
        volatile Map<String, String> headers;
        // Capture 到的 BidiAppend 请求体（用于后续心跳复用/微调）
        volatile byte[] templateBody;
        volatile int heartbeatSeq;
        volatile long lastActiveAtMs;
        volatile int sendFailures;
        volatile ScheduledFuture<?> future;

        SessionTaskState(String sessionId) {
            this.sessionId = sessionId;
            this.lastActiveAtMs = System.currentTimeMillis();
            this.heartbeatSeq = 0;
        }
    }

    private static void bootstrapSessionTask(String sessionId) {
        if (StrUtil.isBlank(sessionId)) {
            return;
        }
        SessionTaskState state = SESSION_TASKS.computeIfAbsent(sessionId, SessionTaskState::new);
        state.lastActiveAtMs = System.currentTimeMillis();
        if (state.taskStarted) {
            return;
        }
        synchronized (state) {
            if (state.taskStarted) {
                return;
            }
            state.future = HEARTBEAT_EXECUTOR.scheduleWithFixedDelay(
                    () -> runHeartbeatTick(sessionId), HEARTBEAT_INTERVAL.toMillis(),
                    HEARTBEAT_INTERVAL.toMillis(), TimeUnit.MILLISECONDS);
            state.taskStarted = true;
            LOG.info(() -> String.format("[CursorAbort][Heartbeat] session task started session=%s", sessionId));
        }
    }

    private static void captureBidiAppendHeaders(String sessionId, String host, HttpHeaders headers) {
        if (StrUtil.isBlank(sessionId) || headers == null) {
            return;
        }
        SessionTaskState state = SESSION_TASKS.computeIfAbsent(sessionId, SessionTaskState::new);
        state.lastActiveAtMs = System.currentTimeMillis();
        state.host = host;
        state.headers = sanitizeHeaders(headers);
        state.readyToSend = state.headers != null && !state.headers.isEmpty();
        LOG.info(() -> String.format("[CursorAbort][Heartbeat] captured headers session=%s ready=%s",
                sessionId, state.readyToSend));
    }

    private static void captureBidiAppendTemplate(String sessionId, byte[] body) {
        if (StrUtil.isBlank(sessionId) || body == null || body.length == 0) {
            return;
        }
        if (!isHeartbeatTemplateBody(body)) {
            return;
        }
        SessionTaskState state = SESSION_TASKS.computeIfAbsent(sessionId, SessionTaskState::new);
        state.lastActiveAtMs = System.currentTimeMillis();
        // clone 一份，避免后续写 buffer 时被污染
        state.templateBody = Arrays.copyOf(body, body.length);
        LOG.fine(() -> String.format(
                "[CursorAbort][Heartbeat] captured heartbeat template session=%s bodyBytes=%d",
                sessionId, body.length));
    }

    private static void runHeartbeatTick(String sessionId) {
        SessionTaskState state = SESSION_TASKS.get(sessionId);
        if (state == null) {
            return;
        }
        long idleMs = System.currentTimeMillis() - state.lastActiveAtMs;
        if (idleMs > SESSION_IDLE_TTL.toMillis()) {
            stopAndRemoveSession(sessionId, "idle_timeout");
            return;
        }
        if (!state.readyToSend || state.headers == null || state.headers.isEmpty()) {
            LOG.fine(() -> String.format("[CursorAbort][Heartbeat] waiting session=%s headersReady=%s",
                    sessionId, state.headers != null && !state.headers.isEmpty()));
            return;
        }
        boolean ok = sendHeartbeatOnce(state);
        if (ok) {
            state.sendFailures = 0;
            state.lastActiveAtMs = System.currentTimeMillis();
            LOG.info(() -> String.format("[CursorAbort][Heartbeat] sent session=%s", sessionId));
        } else {
            state.sendFailures++;
            LOG.warning(() -> String.format("[CursorAbort][Heartbeat] send failed session=%s failCount=%d",
                    sessionId, state.sendFailures));
            if (state.sendFailures >= MAX_SEND_FAILS) {
                stopAndRemoveSession(sessionId, "max_failures");
            }
        }
        sendCustomUserAppendMsg(state, "帮我写个五子棋html");
    }

    private static boolean sendHeartbeatOnce(SessionTaskState state) {
        String host = StrUtil.isBlank(state.host) ? "api2.cursor.sh" : state.host;
        String requestId = state.headers == null ? null : state.headers.get("x-request-id");
        if (StrUtil.isBlank(requestId)) {
            // 兜底：至少保证 body 非空，避免 500，但该请求很可能仍会被服务端拒绝
            requestId = state.sessionId;
        }
        int seq = state.heartbeatSeq + 1;
        state.heartbeatSeq = seq;

        byte[] body;
        // 优先复用捕获到的真实模板包，这样后续如果需要“改原 body”，直接在模板上打补丁即可。
        if (state.templateBody != null && state.templateBody.length > 0) {
            body = patchHeartbeatBody(state.templateBody, requestId, seq);
        } else {
            body = buildNoInteractionHeartbeatBody(requestId, seq);
        }
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://" + host + "/aiserver.v1.BidiService/BidiAppend");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout((int) Duration.ofSeconds(5).toMillis());
            conn.setReadTimeout((int) Duration.ofSeconds(8).toMillis());
            conn.setDoOutput(true);
            conn.setRequestProperty("content-type", "application/proto");
            conn.setRequestProperty("connect-protocol-version", "1");
            if (state.headers != null) {
                for (Map.Entry<String, String> e : state.headers.entrySet()) {
                    String key = e.getKey();
                    if (key == null) {
                        continue;
                    }
                    String low = key.toLowerCase();
                    if (HOP_HEADERS.contains(low) || !HEARTBEAT_HEADER_ALLOWLIST.contains(low)) {
                        continue;
                    }
                    conn.setRequestProperty(key, e.getValue());
                }
            }
            // 按你的要求：x-original-request-id 取 x-request-id 的值
//            conn.setRequestProperty("x-original-request-id", requestId);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
            int code = conn.getResponseCode();
            return code >= 200 && code < 300;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "[CursorAbort][Heartbeat] send exception session=" + state.sessionId, e);
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
    /**
     * 按日志里 `protobufKind=interaction_update:no_interaction_message` 的 payloadHex 结构构建心跳 body。
     *
     * 观测到的 wire 形态（十六进制）大致为：
     *  - 0a <len(field1Bytes)> <field1Bytes>                  (field1)
     *  - 12 26 0a 24 <requestId(36 bytes ascii uuid)>        (field2)
     *  - 18 <varint(seq)>                                    (field3)
     *
     * field1Bytes：
     *  - seq==1: "1a021a00"
     *  - seq>=2: "1a0408" + twoDigits(seq-1) + "1a00"
     */
    private static byte[] buildNoInteractionHeartbeatBody(String requestId, int seq) {
        byte[] uuidBytes = requestId.getBytes(StandardCharsets.UTF_8);
        byte[] field1Bytes;
        String field1;
        if (seq <= 1) {
            field1 = "1a021a00";
        } else {
            int m = (seq - 1) % 100;
            field1 = "1a0408" + String.format("%02d", m) + "1a00";
        }
        field1Bytes = field1.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        // field1: 0a <len> <bytes>
        out.write(0x0a);
        out.write(field1Bytes.length);
        out.write(field1Bytes, 0, field1Bytes.length);

        // field2: 12 26 (len=38) + inner: 0a 24 + uuid(36 bytes)
        out.write(0x12);
        out.write(0x26);
        out.write(0x0a);
        out.write(0x24);
        if (uuidBytes.length >= 36) {
            out.write(uuidBytes, 0, 36);
        } else {
            // uuidBytes 长度不足 36 会导致 wire 长度不一致，服务端可能拒绝
            out.write(uuidBytes, 0, uuidBytes.length);
        }

        // field3: 18 <varint(seq)>
        byte[] seqVarint = encodeVarint(seq);
        out.write(0x18);
        out.write(seqVarint, 0, seqVarint.length);
        return out.toByteArray();
    }

    private static byte[] patchHeartbeatBody(byte[] templateBody, String requestId, int seq) {
        if (templateBody == null || templateBody.length < 8) {
            return buildNoInteractionHeartbeatBody(requestId, seq);
        }

        // 期望 wire：0a <len(field1)> <field1-bytes> ... 其中 field2/field3 位置依赖 field1 长度
        if ((templateBody[0] & 0xFF) != 0x0a) {
            return buildNoInteractionHeartbeatBody(requestId, seq);
        }

        byte[] uuidBytes = requestId.getBytes(StandardCharsets.UTF_8);
        if (uuidBytes.length != 36) {
            return buildNoInteractionHeartbeatBody(requestId, seq);
        }

        int oldField1Len = templateBody[1] & 0xFF;
        int oldField1EndExclusive = 2 + oldField1Len;
        if (oldField1EndExclusive < 0 || oldField1EndExclusive > templateBody.length) {
            return buildNoInteractionHeartbeatBody(requestId, seq);
        }

        // 重新生成 field1（仅替换这段，其余部分尽量沿用模板）
        String field1;
        if (seq <= 1) {
            field1 = "1a021a00";
        } else {
            int m = (seq - 1) % 100;
            field1 = "1a0408" + String.format("%02d", m) + "1a00";
        }
        byte[] newField1Bytes = field1.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream out = new ByteArrayOutputStream(templateBody.length + 16);
        out.write(0x0a);
        out.write(newField1Bytes.length);
        out.write(newField1Bytes, 0, newField1Bytes.length);
        out.write(templateBody, oldField1EndExclusive, templateBody.length - oldField1EndExclusive);
        byte[] patched = out.toByteArray();

        // patch requestId（field2 内嵌 uuid）
        byte[] marker = new byte[]{0x12, 0x26, 0x0a, 0x24};
        int markerIdx = -1;
        outer:
        for (int i = 0; i <= patched.length - marker.length; i++) {
            for (int j = 0; j < marker.length; j++) {
                if (patched[i + j] != marker[j]) {
                    continue outer;
                }
            }
            markerIdx = i;
            break;
        }
        if (markerIdx >= 0) {
            int uuidStart = markerIdx + marker.length;
            if (uuidStart + 36 <= patched.length) {
                System.arraycopy(uuidBytes, 0, patched, uuidStart, 36);
            }
        }

        // patch field3 varint seq：tag(0x18) + varint(seq)
        int lastTagIdx = -1;
        for (int i = patched.length - 1; i >= 0; i--) {
            if (patched[i] == 0x18) {
                lastTagIdx = i;
                break;
            }
        }
        if (lastTagIdx >= 0 && lastTagIdx + 1 < patched.length) {
            int p = lastTagIdx + 1;
            while (p < patched.length) {
                int b = patched[p] & 0xFF;
                if (b < 0x80) {
                    break;
                }
                p++;
            }
            if (p < patched.length) {
                int afterOldVarintExclusive = p + 1;
                byte[] seqVarint = encodeVarint(seq);
                byte[] prefix = Arrays.copyOfRange(patched, 0, lastTagIdx);
                byte[] suffix = Arrays.copyOfRange(patched, afterOldVarintExclusive, patched.length);
                byte[] newBody = new byte[prefix.length + 1 + seqVarint.length + suffix.length];
                int off = 0;
                System.arraycopy(prefix, 0, newBody, off, prefix.length);
                off += prefix.length;
                newBody[off++] = 0x18;
                System.arraycopy(seqVarint, 0, newBody, off, seqVarint.length);
                off += seqVarint.length;
                if (suffix.length > 0) {
                    System.arraycopy(suffix, 0, newBody, off, suffix.length);
                }
                return newBody;
            }
        }

        return patched;
    }

    /**
     * 发送自定义的 user_message_appended 类型消息到 Cursor BidiAppend 接口
     *
     * @param state 会话状态，包含认证信息和headers
     * @param msg 用户消息内容（纯文本）
     * @return 是否发送成功
     */
    private static boolean sendCustomUserAppendMsg(SessionTaskState state, String msg) {
        if (StrUtil.isBlank(msg)) {
            LOG.warning("[CursorAbort][UserMsg] message is empty, skip sending");
            return false;
        }

        String host = StrUtil.isBlank(state.host) ? "api2.cursor.sh" : state.host;
        String requestId = state.headers == null ? null : state.headers.get("x-request-id");
        String sessionId = state.sessionId;

        if (StrUtil.isBlank(requestId)) {
            requestId = java.util.UUID.randomUUID().toString();
            // 避免 lambda 捕获“会被重新赋值”的变量（不是 effective final）
            LOG.info(String.format("[CursorAbort][UserMsg] generated new requestId=%s", requestId));
        }

        // 构建 user_message_appended 类型的 protobuf 消息体
        byte[] body = buildUserMessageAppendedBody(requestId, msg);

        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://" + host + "/aiserver.v1.BidiService/BidiAppend");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout((int) Duration.ofSeconds(5).toMillis());
            conn.setReadTimeout((int) Duration.ofSeconds(10).toMillis());
            conn.setDoOutput(true);

            // 设置关键请求头
            conn.setRequestProperty("content-type", "application/proto");
            conn.setRequestProperty("connect-protocol-version", "1");

            // 复制必要的认证和上下文headers
            if (state.headers != null) {
                for (Map.Entry<String, String> e : state.headers.entrySet()) {
                    String key = e.getKey();
                    if (key == null) {
                        continue;
                    }
                    String low = key.toLowerCase();
                    if (HOP_HEADERS.contains(low) || !HEARTBEAT_HEADER_ALLOWLIST.contains(low)) {
                        continue;
                    }
                    conn.setRequestProperty(key, e.getValue());
                }
            }

            // 确保使用正确的 request-id 和 session-id
            conn.setRequestProperty("x-request-id", requestId);
            if (StrUtil.isNotBlank(sessionId)) {
                conn.setRequestProperty("x-session-id", sessionId);
            }

            // 写入消息体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
                os.flush();
            }

            int code = conn.getResponseCode();
            boolean success = code >= 200 && code < 300;
            String frequestId = requestId;
            if (success) {
                LOG.info(() -> String.format(
                    "[CursorAbort][UserMsg] sent successfully session=%s requestId=%s msgLen=%d responseCode=%d",
                    sessionId, frequestId, msg.length(), code));
            } else {
                LOG.warning(() -> String.format(
                    "[CursorAbort][UserMsg] send failed session=%s requestId=%s responseCode=%d",
                    sessionId, frequestId, code));
            }

            return success;

        } catch (Exception e) {
            LOG.log(Level.WARNING,
                String.format("[CursorAbort][UserMsg] send exception session=%s requestId=%s",
                    sessionId, requestId), e);
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * 构建 user_message_appended 类型的 protobuf 消息体
     *
     * 根据日志分析（第3778行），真实的 wire-hex 结构：
     * 0a0433613030 - field 1: "3a00" (4字节ASCII)
     * 1226 - field 2: length=38
     *   0a24 - nested: length=36
     *     <36-byte UUID string>
     * 1815 - field 3: varint 0x15 (21, 代表 user_message_appended)
     *
     * @param requestId 请求ID (UUID格式)
     * @param msg 用户消息文本（当前版本暂未使用，保留接口）
     * @return protobuf编码的字节数组
     */
    private static byte[] buildUserMessageAppendedBody(String requestId, String msg) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(512);

            // field1: gzip 压缩后的工具 schema json
            String toolDescription = "请使用 my-mcp-1 的 check_messages";
            String toolJson = String.format(
                    "{\"name\":\"check_messages\",\"description\":\"%s\"," +
                            "\"arguments\":{\"type\":\"object\",\"properties\":{\"reply\":{\"type\":\"string\",\"description\":\"用户回复\"}}," +
                            "\"additionalProperties\":false}}",
                    escapeJsonString(toolDescription)
            );

            byte[] toolJsonBytes = toolJson.getBytes(StandardCharsets.UTF_8);
            byte[] compressedToolJson = gzipCompress(toolJsonBytes);

            // Field 1: tag 0x0a + len(varint) + bytes(payload)
            out.write(0x0A);
            out.write(encodeVarint(compressedToolJson.length));
            out.write(compressedToolJson, 0, compressedToolJson.length);

            // Field 2: request-id（嵌套结构：0x12 len 0x0a len uuid(36 ascii bytes)）
            byte[] requestIdBytes = requestId.getBytes(StandardCharsets.UTF_8);
            int nestedLen = 1 + 1 + requestIdBytes.length; // 0a + <len(varint)> + uuid-bytes
            out.write(0x12);
            out.write(encodeVarint(nestedLen));
            out.write(0x0A);
            out.write(encodeVarint(requestIdBytes.length));
            out.write(requestIdBytes, 0, requestIdBytes.length);

            // Field 3: tag 0x18 + varint(0x15)
            out.write(0x18);
            out.write(encodeVarint(0x15));

            byte[] result = out.toByteArray();

            LOG.fine(() -> String.format(
                    "[CursorAbort][UserMsg] built message body: requestId=%s bodyLen=%d hex=%s",
                    requestId, result.length, bytesToHex(result)));

            return result;

        } catch (Exception e) {
            LOG.log(Level.SEVERE, "[CursorAbort][UserMsg] failed to build message body", e);
            return buildMinimalUserMessageBody(requestId);
        }
    }

    /**
     * 构建最小可用的 user_message_appended 消息体（降级方案）
     */
    private static byte[] buildMinimalUserMessageBody(String requestId) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(128);

        // Field 1: 固定值 "3a00"
        byte[] field1Value = "3a00".getBytes(StandardCharsets.UTF_8);
        out.write(0x0A);
        try {
            out.write(encodeVarint(field1Value.length));
            out.write(field1Value, 0, field1Value.length);
        } catch (Exception e) {
            // ignore
        }

        // Field 2: request-id (嵌套结构)
        byte[] requestIdBytes = requestId.getBytes(StandardCharsets.UTF_8);
        int nestedLen = 1 + 1 + requestIdBytes.length;

        try {
            out.write(0x12);
            out.write(encodeVarint(nestedLen));
            out.write(0x0A);
            out.write(encodeVarint(requestIdBytes.length));
            out.write(requestIdBytes, 0, requestIdBytes.length);
            // Field 3: 消息类型标识
            out.write(0x18);
            out.write(encodeVarint(0x15));
        } catch (Exception e) {
            // ignore
        }



        return out.toByteArray();
    }

    /**
     * Gzip压缩数据
     */
    private static byte[] gzipCompress(byte[] data) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             java.util.zip.GZIPOutputStream gzos = new java.util.zip.GZIPOutputStream(baos)) {
            gzos.write(data);
            gzos.finish();
            return baos.toByteArray();
        } catch (Exception e) {
            LOG.log(Level.WARNING, "[CursorAbort][UserMsg] gzip compress failed, using raw data", e);
            return data;
        }
    }

    /**
     * 转义JSON字符串中的特殊字符
     */
    private static String escapeJsonString(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * 将字节数组转换为十六进制字符串（用于调试）
     */
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static byte[] encodeVarint(int value) {
        // protobuf varint: 7 bits per byte, continuation bit 0x80
        if (value < 0) {
            return new byte[]{0x00};
        }
        byte[] tmp = new byte[5];
        int pos = 0;
        int v = value;
        while (true) {
            int b = v & 0x7F;
            v >>>= 7;
            if (v == 0) {
                tmp[pos++] = (byte) b;
                break;
            }
            tmp[pos++] = (byte) (b | 0x80);
        }
        return Arrays.copyOf(tmp, pos);
    }

    private static Map<String, String> sanitizeHeaders(HttpHeaders headers) {
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<String, String> e : headers) {
            String key = e.getKey();
            if (key == null) {
                continue;
            }
            String low = key.toLowerCase();
            if (HOP_HEADERS.contains(low) || "host".equals(low)) {
                continue;
            }
            if (!HEARTBEAT_HEADER_ALLOWLIST.contains(low)) {
                continue;
            }
            out.put(key, e.getValue());
        }
        return out;
    }

    private static void stopAndRemoveSession(String sessionId, String reason) {
        SessionTaskState state = SESSION_TASKS.remove(sessionId);
        if (state == null) {
            return;
        }
        ScheduledFuture<?> future = state.future;
        if (future != null) {
            future.cancel(false);
        }
        LOG.info(() -> String.format("[CursorAbort][Heartbeat] task stopped session=%s reason=%s",
                sessionId, reason));
    }

    private static String normalizePathOnly(String uri) {
        if (uri == null) {
            return null;
        }
        int q = uri.indexOf('?');
        return q >= 0 ? uri.substring(0, q) : uri;
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

    private static String valueOrDash(String s) {
        return (s == null || s.isEmpty()) ? "-" : s;
    }

    /**
     * 公开API：向指定会话发送自定义用户消息
     *
     * @param sessionId 会话ID
     * @param userMessage 用户消息内容
     * @return 是否发送成功
     */
    public static boolean sendMessageToSession(String sessionId, String userMessage) {
        if (StrUtil.isBlank(sessionId)) {
            LOG.warning("[CursorAbort][API] sessionId is blank");
            return false;
        }

        SessionTaskState state = SESSION_TASKS.get(sessionId);
        if (state == null) {
            LOG.warning(() -> String.format("[CursorAbort][API] session not found: %s", sessionId));
            return false;
        }

        if (!state.readyToSend) {
            LOG.warning(() -> String.format(
                "[CursorAbort][API] session not ready (missing headers): %s", sessionId));
            return false;
        }

        LOG.info(() -> String.format(
            "[CursorAbort][API] sending custom message session=%s msgLen=%d",
            sessionId, userMessage != null ? userMessage.length() : 0));

        return sendCustomUserAppendMsg(state, userMessage);
    }

    /**
     * 公开API：获取所有活跃会话ID列表
     *
     * @return 活跃会话ID集合
     */
    public static Set<String> getActiveSessions() {
        return SESSION_TASKS.keySet();
    }

    private static boolean isHeartbeatTemplateBody(byte[] wireBody) {
        if (wireBody == null || wireBody.length == 0) {
            return false;
        }
        byte[] payload = decodePayloadForKind(wireBody);
        if (payload == null || payload.length == 0) {
            return false;
        }
        String kind = ConnectProtoUtil.describeAgentServerMessageKind(payload);
        if (kind != null && kind.contains("no_interaction_message")) {
            return true;
        }
        // 兜底：一些版本可能返回 unknown_wire_type_* 但体积较小，作为心跳候选。
        return kind != null && kind.startsWith("interaction_update:unknown_wire_type_") && payload.length <= 96;
    }

    private static byte[] decodePayloadForKind(byte[] body) {
        if (isGzipMagic(body)) {
            return ConnectProtoUtil.gzipDecompress(body);
        }
        if (looksLikeConnectFrame(body)) {
            return ConnectProtoUtil.extractPayloadFromWire(body);
        }
        return body;
    }

    private static boolean isGzipMagic(byte[] body) {
        return body != null && body.length >= 2
                && (body[0] & 0xFF) == 0x1f
                && (body[1] & 0xFF) == 0x8b;
    }

    private static boolean looksLikeConnectFrame(byte[] body) {
        if (body == null || body.length < 5) {
            return false;
        }
        int typeByte = body[0] & 0xFF;
        if (typeByte > 3) {
            return false;
        }
        int payloadLen = ((body[1] & 0xFF) << 24)
                | ((body[2] & 0xFF) << 16)
                | ((body[3] & 0xFF) << 8)
                | (body[4] & 0xFF);
        return payloadLen >= 0 && payloadLen <= body.length - 5;
    }
}
