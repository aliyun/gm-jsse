package com.aliyun.handshake;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.assertFalse;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ServerKeyExchangeTest {

    private X509Certificate getSignCertificate() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        FileInputStream is = new FileInputStream("resources/sm_https_proxy_sign.pem");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        return cert;
    }

    private X509Certificate getEncCertificate() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        FileInputStream is = new FileInputStream("resources/sm_https_proxy_enc.pem");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        return cert;
    }

    @Test
    public void getBytesTest() throws Exception {
        byte[] bytes = new byte[]{66};
        ServerKeyExchange exchange = new ServerKeyExchange(bytes);
        bytes = exchange.getBytes();
        Assert.assertEquals(0, bytes[0]);
        Assert.assertEquals(1, bytes[1]);
        Assert.assertEquals(66, bytes[2]);
    }

    @Test
    public void toStringTest() throws Exception {
        byte[] bytes = new byte[]{10};
        ServerKeyExchange exchange = new ServerKeyExchange(bytes);
        Assert.assertTrue(exchange.toString().contains("signedParams = 0a"));
    }

    @Test
    public void verifyTest() throws Exception {
        byte[] bytes = new byte[]{10};
        ServerKeyExchange exchange = Mockito.spy(new ServerKeyExchange(bytes));
        X509Certificate encryptionCert = getEncCertificate();
        PublicKey key = getSignCertificate().getPublicKey();
        boolean verified = exchange.verify(key, bytes, bytes, encryptionCert);
        assertFalse(verified);
    }
}
