package com.aliyun.gmsse.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import com.aliyun.gmsse.GMProvider;

public class ClientTest {

    public static Runnable runServer() {
        return new Runnable() {
            @Override
            public void run() {
                try {
                    Server server = new Server();
                    SSLServerSocket ss = server.buildServerSocket();

                    SSLSocket socket = (SSLSocket) ss.accept();

                    // get path to class file from header
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    String line;
                    do {
                        line = in.readLine();
                        System.out.println(line);
                    } while ((line.length() != 0) &&
                            (line.charAt(0) != '\r') && (line.charAt(0) != '\n'));

                    PrintWriter ps = new PrintWriter(socket.getOutputStream(), false);
                    String content = "<!DOCTYPE html>\r\n" + "Hi.\r\n";
                    int contentLength = content.getBytes().length;
                    ps.print("HTTP/1.1 200 OK\r\n");
                    ps.print("Content-Type: text/html\r\n");
                    ps.print("Connection: close\r\n");
                    ps.print("Content-Length:" + contentLength + "\r\n");
                    ps.print("\r\n");
                    ps.print(content);
                    ps.flush();
                    socket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        };
    }

    @Test
    public void testServer() throws NoSuchAlgorithmException, KeyStoreException, CertificateException,
            IOException, KeyManagementException, InterruptedException, URISyntaxException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

        Runnable runner = runServer();
        Thread thread = new Thread(runner, "server");
        thread.start();
        Thread.sleep(1000);
        BouncyCastleProvider bc = new BouncyCastleProvider();
        KeyStore ks = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        InputStream is = ClientTest.class.getClassLoader().getResourceAsStream("sm2/chain-ca.crt");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        ks.load(null, null);
        ks.setCertificateEntry("gmca", cert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);
        sc.init(null, tmf.getTrustManagers(), null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        URI uri = new URI("https://localhost:8443/");
        URL serverUrl = uri.toURL();
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setSSLSocketFactory(ssf);
        conn.setRequestMethod("GET");
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", conn.getCipherSuite());

        // 读取服务器端返回的内容
        InputStream connInputStream = conn.getInputStream();
        InputStreamReader isReader = new InputStreamReader(connInputStream, "utf-8");
        BufferedReader br = new BufferedReader(isReader);
        StringBuffer buffer = new StringBuffer();
        String line = null;
        while ((line = br.readLine()) != null) {
            buffer.append(line);
        }
        Assert.assertEquals("<!DOCTYPE html>Hi.", buffer.toString());
        connInputStream.close();
        // 中断服务线程
        thread.interrupt();
    }
}
