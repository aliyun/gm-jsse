package com.aliyun.gmsse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Assert;
import org.junit.Test;

public class MainTest {
    @Test
    public void test() throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, UnrecoverableKeyException, URISyntaxException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

        // load CA
        X509Certificate cert = Helper.loadCertificate("WoTrus-SM2.crt");
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setCertificateEntry("gmca", cert);

        // init trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, null);
        KeyManager[] kms = kmf.getKeyManagers();

        sc.init(kms, tmf.getTrustManagers(), null);

        SSLSocketFactory ssf = sc.getSocketFactory();

        URI serverUrl = new URI("https://sm2only.ovssl.cn/");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.toURL().openConnection();
        conn.setRequestMethod("GET");
        conn.setSSLSocketFactory(ssf);
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
        Assert.assertTrue(buffer.toString().contains("沃通"));
        connInputStream.close();
    }
}
