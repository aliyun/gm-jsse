package com.aliyun.gmsse.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;

import com.aliyun.gmsse.GMProvider;

public class ClientTest {

    public static void main(String[] args) throws NoSuchAlgorithmException, KeyStoreException, CertificateException,
            IOException, KeyManagementException, InterruptedException, URISyntaxException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

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
        // URL serverUrl = new URL("https://sm2only.ovssl.cn/");
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
    }
}
