package com.github.monkeywie.proxyee;

import cn.hutool.core.thread.ThreadUtil;
import org.glassfish.tyrus.client.ClientManager;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.websocket.*;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

@ClientEndpoint
public class WebSocketClient {

    private Session session;

    @OnOpen
    public void onOpen(Session session) {
        this.session = session;
        System.out.println("Connected to server");
    }

    @OnMessage
    public void onMessage(String message) {
        System.out.println("Received: " + message);
    }

    @OnClose
    public void onClose(Session session, CloseReason closeReason) {
        System.out.println("Session closed: " + closeReason);
    }

    public static void main(String[] args) {
        try {
            // 信任所有证书
            trustAllCertificates();

            // 创建 WebSocket 客户端容器
            ClientManager client = ClientManager.createClient();

            // 设置 SSL 上下文
            client.getProperties().put("org.glassfish.tyrus.client.ssl.context", getTrustAllSslContext());

            // 设置代理
            System.setProperty("http.proxyHost", "localhost");
            System.setProperty("http.proxyPort", "9999");
            System.setProperty("https.proxyHost", "localhost");
            System.setProperty("https.proxyPort", "9999");

            // 连接到 WebSocket 服务器
            Session session = client.connectToServer(WebSocketClient.class, URI.create("wss://im-linkserver-62.csdn.net/"));
//            Session session = client.connectToServer(WebSocketClient.class, URI.create("ws://10.10.20.100/gateway/notify-service/socket?clientId=pc&Authorization=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjYWNoZUtleSI6IkNPTlNPTEU6VVNFUl9UT0tFTjpjaGVucXA6MjkxNDc1NDE4NzkxMTI2MjIwOCIsImNsaWVudENvZGUiOiI4MDAiLCJpc3MiOiJNSU5HIiwiaXNBcHAiOiJmYWxzZSIsInVzZXJDb2RlIjoiY2hlbnFwIn0.53Ve46GKvEMOLvzl4lPtRb4HN-gz2vXyGibuMhSnREw"));

//            // 发送消息示例
//            session.getBasicRemote().sendText("666");
            session.getBasicRemote().sendText("{\n" +
                    "    \"ver\": \"1.0\",\n" +
                    "    \"cmdId\": 2,\n" +
                    "    \"isZip\": 0,\n" +
                    "    \"body\": {\n" +
                    "        \"userId\": \"qq_35215932\",\n" +
                    "        \"appId\": \"CSDN-PC\",\n" +
                    "        \"imToken\": \"172714398821870MNuFhe\",\n" +
                    "        \"groupId\": \"CSDN-private-MSG\"\n" +
                    "    }\n" +
                    "}");
            while (true) {
                // 等待用户输入消息
                ThreadUtil.sleep(2000);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SSLContext getTrustAllSslContext() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        return sc;
    }

    private static void trustAllCertificates() {
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };

        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
    }
}
