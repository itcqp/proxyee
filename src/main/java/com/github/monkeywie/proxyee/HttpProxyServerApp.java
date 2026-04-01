package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.intercept.common.CertDownIntercept;
import com.github.monkeywie.proxyee.intercept.cursor.CursorStreamAbortIntercept;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;

/**
 * 启动带 HTTPS MITM 与 Cursor 流式中止拦截的代理。
 */
public class HttpProxyServerApp {
    public static void main(String[] args) {
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
                        pipeline.addLast(new CursorStreamAbortIntercept());
                    }
                })
                .start(port);
    }
}
