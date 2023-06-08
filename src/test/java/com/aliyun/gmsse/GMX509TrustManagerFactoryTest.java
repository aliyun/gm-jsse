package com.aliyun.gmsse;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

public class GMX509TrustManagerFactoryTest {

    @Test
    public void initTest() throws NoSuchAlgorithmException {
        TrustManagerFactory fact = TrustManagerFactory.getInstance("X509", new GMProvider());
        try {
            fact.getTrustManagers();
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("not initialized", e.getMessage());
        }
    }

    @Test
    public void initWithCertTest() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        BouncyCastleProvider bc = new BouncyCastleProvider();
        KeyStore ks = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("sm2/chain-ca.crt");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        ks.load(null, null);
        ks.setCertificateEntry("alias", cert);

        TrustManagerFactory fact = TrustManagerFactory.getInstance("X509", new GMProvider());
        fact.init(ks);
        TrustManager[] tms = fact.getTrustManagers();
        Assert.assertEquals(1, tms.length);
        X509TrustManager tm = (X509TrustManager)tms[0];
        X509Certificate[] issuers = tm.getAcceptedIssuers();
        Assert.assertEquals(1, issuers.length);
    }

    @Test
    public void initWithNoCertTest() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);

        TrustManagerFactory fact = TrustManagerFactory.getInstance("X509", new GMProvider());
        fact.init(ks);
        TrustManager[] tms = fact.getTrustManagers();
        Assert.assertEquals(1, tms.length);
        X509TrustManager tm = (X509TrustManager)tms[0];
        X509Certificate[] issuers = tm.getAcceptedIssuers();
        Assert.assertEquals(0, issuers.length);
    }
}
