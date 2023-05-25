package com.aliyun.gmsse.server;

import java.io.FileInputStream;
import java.io.IOException;
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
import org.junit.Test;

import com.aliyun.gmsse.GMProvider;


public class ClientTest {

    @Test
    public void testClient() throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException, KeyManagementException {

        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

        BouncyCastleProvider bc = new BouncyCastleProvider();
        KeyStore ks = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        FileInputStream is = new FileInputStream(
                this.getClass().getClassLoader().getResource("WoTrus-SM2.crt").getFile());
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        ks.load(null, null);
        ks.setCertificateEntry("gmca", cert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);
        sc.init(null, tmf.getTrustManagers(), null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        URL serverUrl = new URL("https://localhost:8443/");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", conn.getCipherSuite());
    }
}
