package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.intercept.cursor.CursorHttp2StreamAbortIntercept;

import java.util.logging.Logger;

/**
 * 启动 Cursor HTTP/2 流式中转服务器。
 *
 * <p>作为 MITM 代理入口时，客户端可走 HTTP/1.1；上游 HTTP/2 聊天流一律强制
 * {@code /aiserver.v1.ChatService/StreamUnifiedChatWithTools}；客户端若走 {@code /agent.v1.AgentService/RunSSE}，
 * 代理<strong>透传</strong>该路径与原始请求体（不再改写为 UnifiedChat，以免响应 protobuf 与 connect-es 解码不一致）；
 * 上游 HTTP/2 响应：RunSSE 且 200 时，若客户端<strong>未</strong>显式 {@code Accept: text/event-stream}，
 * 则对 IDE 下行<strong>透传</strong> Connect 二进制分块（与 <a href="https://github.com/burpheart/cursor-tap">cursor-tap</a> 对 Connect 帧流的解析模型一致）；
 * 仅当 Accept 含 event-stream 时，才格式化为 SSE，{@code data:} 使用 {@code messageType}/{@code text} 形 JSON（见 {@link com.github.monkeywie.proxyee.connect.SseDownstreamFormatter#connectMsg0Json}），末行 {@code data: [DONE]}。对匹配流做终止串扫描（Connect 解压后匹配）。
 *
 * <p>用法：{@code java -cp ... HttpProxyServerApp [port]}（默认端口 8080）
 */
public class HttpProxyServerApp {

    private static final Logger LOG = Logger.getLogger(HttpProxyServerApp.class.getName());

    public static void main(String[] args) throws Exception {
        int port = 8080;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }

        CursorHttp2StreamAbortIntercept h2Server = new CursorHttp2StreamAbortIntercept(
                CursorHttp2StreamAbortIntercept.DEFAULT_ABORT_TOKEN,
                null /* 如需修改头，传入 headers -> headers.set("x-foo", "bar") */
        );
        h2Server.start(port);
        LOG.info("[H2Proxy] started on port " + port + ", waiting for Cursor IDE requests...");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.info("[H2Proxy] shutting down...");
            h2Server.stop();
        }));
    }
}
