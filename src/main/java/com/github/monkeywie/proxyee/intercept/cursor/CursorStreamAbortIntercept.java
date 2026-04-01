package com.github.monkeywie.proxyee.intercept.cursor;

import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.handler.codec.http.*;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;

import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Host 含 cursor.sh 时扫描响应体；命中 zmgnb666 则先转发当前分块再断上游。 */
public class CursorStreamAbortIntercept extends HttpProxyIntercept {

    private static final Logger LOG = Logger.getLogger(CursorStreamAbortIntercept.class.getName());

    public static final String DEFAULT_ABORT_TOKEN = "zmgnb666";

    private static final AttributeKey<CursorAbortState> STATE =
            AttributeKey.valueOf("cursorStreamAbortState");

    private final String abortToken;

    public CursorStreamAbortIntercept() {
        this(DEFAULT_ABORT_TOKEN);
    }

    public CursorStreamAbortIntercept(String abortToken) {
        if (abortToken == null || abortToken.isEmpty()) {
            throw new IllegalArgumentException("abortToken");
        }
        this.abortToken = abortToken;
    }

    @Override
    public void beforeRequest(Channel clientChannel, HttpRequest httpRequest,
                              HttpProxyInterceptPipeline pipeline) throws Exception {
        String host = hostFrom(httpRequest);
        boolean watch = host != null && host.toLowerCase().contains("cursor.sh") && host.toLowerCase().contains("api");
        if (watch) {
            CursorAbortState st = new CursorAbortState();
            st.abortNeedle = abortToken.getBytes(StandardCharsets.UTF_8);
            st.overlap = Math.max(0, st.abortNeedle.length - 1);
            clientChannel.attr(STATE).set(st);
            LOG.info(() -> String.format("[CursorAbort] monitor response for host=%s uri=%s", host, httpRequest.uri()));
        } else {
            clientChannel.attr(STATE).remove();
        }
        pipeline.beforeRequest(clientChannel, httpRequest);
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

        if (containsAbortPattern(st.tail, chunk, needle)) {
            LOG.info(() -> String.format(
                    "[CursorAbort] token matched, forwarding chunk then closing upstream (bytes=%d)", n));
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
        if (needle.length == 0) {
            return false;
        }
        int pl = prevTail == null ? 0 : prevTail.length;
        int cl = chunk.length;
        byte[] hay = new byte[pl + cl];
        if (pl > 0) {
            System.arraycopy(prevTail, 0, hay, 0, pl);
        }
        System.arraycopy(chunk, 0, hay, pl, cl);
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
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
        byte[] abortNeedle;
        int overlap;
        byte[] tail;
        boolean aborted;
        boolean decompressorAdded;
        HttpResponse httpResponse;
    }
}
