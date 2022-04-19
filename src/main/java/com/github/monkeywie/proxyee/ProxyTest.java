package com.github.monkeywie.proxyee;


import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.intercept.common.FullResponseIntercept;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import com.github.monkeywie.proxyee.util.HttpUtil;
import io.netty.channel.Channel;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

import java.nio.charset.Charset;

/**
 * @version 1.0.0
 * @Author chenqp
 * @Date 2022/4/14
 * @describe
 */
public class ProxyTest {
    public static void main(String[] args) {
        HttpProxyServerConfig config =  new HttpProxyServerConfig();
//开启HTTPS支持
//不开启的话HTTPS不会被拦截，而是直接转发原始报文
        config.setHandleSsl(true);
        new HttpProxyServer()
                .serverConfig(config)
                .proxyInterceptInitializer(new HttpProxyInterceptInitializer() {
                    @Override
                    public void init(HttpProxyInterceptPipeline pipeline) {
                        pipeline.addLast(new FullResponseIntercept() {

                            @Override
                            public boolean match(HttpRequest httpRequest, HttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
//                                boolean flag =
//                                        HttpUtil.checkUrl(pipeline.getHttpRequest(), "^aimal-wechat-gate1.xgamevip.com$") || HttpUtil.checkUrl(pipeline.getHttpRequest(), "^aimal-wechat-gate2.xgamevip.com$");
//                                if (flag) {
//                                    System.out.println(66666);
//                                }
//                                return flag;
                                //在匹配到百度首页时插入js
//                                return HttpUtil.checkUrl(pipeline.getHttpRequest(), "^www.baidu.com$")
//                                        && isHtml(httpRequest, httpResponse);
                                return true;
                            }

                            @Override
                            public void handleResponse(HttpRequest httpRequest, FullHttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                                String uri = httpRequest.uri();
                                System.out.println("响应URI"+ uri);
                                if ("/".equals(uri)) {
                                    System.out.println(1);
                                }
                                //打印原始响应信息
//                                System.out.println("响应1："+httpResponse.toString());
//                                System.out.println(Base64.decode(httpResponse.toString()));
//                                Charset charset = Charset.defaultCharset();
                                System.out.println("响应2："+httpResponse.content().toString(Charset.forName("utf-8")));
                                //修改响应头和响应体
//                                httpResponse.headers().set("handel", "edit head");
//                                httpResponse.content().writeBytes("do a test".getBytes());
                            }

                            @Override
                            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent, HttpProxyInterceptPipeline pipeline) throws Exception {
                                System.out.println("响应后："+httpContent.content().toString(Charset.forName("utf-8")));
                                super.afterResponse(clientChannel, proxyChannel, httpContent, pipeline);
                            }
                        });
                    }
                })
                .start(9999);
    }
}
