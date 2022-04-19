package com.github.monkeywie.proxyee.handler.ssl;



import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public final class SecureChatSslContextFactory {

    private static final String PROTOCOL = "TLS";

    private static final String  KEY_PASSWORD="123456";

    private static SSLContext SERVER_CONTEXT;//服务器安全套接字协议

    private static SSLContext CLIENT_CONTEXT;//客户端安全套接字协议


    public static SSLContext getServerContext(String pkPath){
        if(SERVER_CONTEXT!=null) return SERVER_CONTEXT;
        InputStream in =null;

        try{
            //密钥管理器
            KeyManagerFactory kmf = null;
            if(pkPath!=null){
                //密钥库KeyStore
                KeyStore ks = KeyStore.getInstance("JKS");
                //加载服务端证书
                in = new FileInputStream(pkPath);
                //加载服务端的KeyStore
                ks.load(in, KEY_PASSWORD.toCharArray());

                kmf = KeyManagerFactory.getInstance("SunX509");
                //初始化密钥管理器
                kmf.init(ks, KEY_PASSWORD.toCharArray());
            }
            //获取安全套接字协议（TLS协议）的对象
            SERVER_CONTEXT= SSLContext.getInstance(PROTOCOL);
            //初始化此上下文
            //参数一：认证的密钥      参数二：对等信任认证  参数三：伪随机数生成器 。 由于单向认证，服务端不用验证客户端，所以第二个参数为null
            SERVER_CONTEXT.init(kmf.getKeyManagers(), trustAllCerts, null);
//            SERVER_CONTEXT.init(kmf.getKeyManagers(), null, null);

        }catch(Exception e){
            throw new Error("Failed to initialize the server-side SSLContext", e);
        }finally{
            if(in !=null){
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }
        return SERVER_CONTEXT;
    }



    private static final TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
    };

    public static SSLContext getClientContext(String caPath){
        if(CLIENT_CONTEXT!=null) return CLIENT_CONTEXT;

        InputStream inputStream = null;
        try{
            //信任库
            TrustManagerFactory tf = null;



            if (caPath != null) {
                //密钥库KeyStore
                KeyStore tks = KeyStore.getInstance("JKS");
                //加载客户端证书
                inputStream = new FileInputStream(caPath);
                tks.load(inputStream, KEY_PASSWORD.toCharArray());

                try{
                    tf = TrustManagerFactory.getInstance("IBMX509");
                }catch (Exception e){
                    tf = TrustManagerFactory.getInstance("SunX509");
                }


                // 初始化信任库
                tf.init(tks);
            }

            CLIENT_CONTEXT = SSLContext.getInstance(PROTOCOL);
            //设置信任证书
//            CLIENT_CONTEXT.init(null,tf == null ? null : tf.getTrustManagers(), null);
            CLIENT_CONTEXT.init(null,trustAllCerts, null);
        }catch(Exception e){
            throw new Error("Failed to initialize the client-side SSLContext");
        }finally{
            if(inputStream !=null){
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return CLIENT_CONTEXT;
    }

}

