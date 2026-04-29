package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.intercept.common.CertDownIntercept;
import com.github.monkeywie.proxyee.intercept.cursor.CursorHttp2StreamAbortIntercept;
import com.github.monkeywie.proxyee.intercept.cursor.CursorStreamAbortIntercept;
import com.github.monkeywie.proxyee.intercept.cursor.CursorStreamAbortIntercept2;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;

import java.util.logging.Logger;

/**
 * 启动 Cursor MITM HTTP 代理。
 *
 * <p>客户端以 HTTP/1.1 代理方式连接本地端口；代理对 Cursor HTTPS 流量做 MITM，
 * 取到解密后的聊天请求后再通过 OkHttp 以 HTTPS/HTTP2 转发到真实上游。
 * 对流式 Connect 响应做 abort token 扫描，命中后清理当前帧并主动中断上游流。
 *
 * <p>用法：{@code java -cp ... HttpProxyServerApp [port]}（默认端口 8080）
 */
public class HttpProxyServerApp {

    private static final Logger LOG = Logger.getLogger(HttpProxyServerApp.class.getName());

    public static void main(String[] args) throws Exception {
//        int port = 8080;
//        if (args.length > 0) {
//            port = Integer.parseInt(args[0]);
//        }
//
//        CursorHttp2StreamAbortIntercept.setForceRunSseUnifiedChatBridge(true);
//
//        CursorHttp2StreamAbortIntercept h2Server = new CursorHttp2StreamAbortIntercept(
//                CursorHttp2StreamAbortIntercept.DEFAULT_ABORT_TOKEN,
//                null /* 如需修改头，传入 headers -> headers.set("x-foo", "bar") */
//        );
//        h2Server.start(port);
//        LOG.info("[H2Proxy] MITM proxy started on port " + port + ", waiting for Cursor IDE requests...");
//
//        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
//            LOG.info("[H2Proxy] shutting down...");
//            h2Server.stop();
//        }));

        System.out.println("start proxy server (MITM + CursorStreamAbort)");
        int port = 8080;
        if (args.length > 0) {
            port = Integer.valueOf(args[0]);
        }
        HttpProxyServerConfig config = new HttpProxyServerConfig();
        config.setHandleSsl(true);
        new HttpProxyServer()
                .serverConfig(config)
                .proxyInterceptInitializer(new HttpProxyInterceptInitializer() {
                    @Override
                    public void init(HttpProxyInterceptPipeline pipeline) {
                        pipeline.addLast(new CertDownIntercept());
                        pipeline.addLast(new CursorStreamAbortIntercept2());
                    }
                })
                .start(port);
    }
}
