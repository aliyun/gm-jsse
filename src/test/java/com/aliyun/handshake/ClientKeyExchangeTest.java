package com.aliyun.handshake;

import com.aliyun.ProtocolVersion;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClientKeyExchangeTest {

    private X509Certificate getCertificate() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        FileInputStream is = new FileInputStream("resources/sm_https_proxy_enc.pem");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        return cert;
    }

    @Test
    public void getMasterSecretTest() throws Exception {
        SecureRandom random = new SecureRandom();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(ProtocolVersion.NTLS_1_1,
                random, getCertificate());
        byte[] para = new byte[]{32};
        byte[] bytes = clientKeyExchange.getMasterSecret(para, para);
        Assert.assertEquals(48, bytes.length);
    }

    @Test
    public void getPreMasterSecretTest() throws Exception {
        SecureRandom random = new SecureRandom();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(ProtocolVersion.NTLS_1_1,
                random, getCertificate());

        byte[] bytes = clientKeyExchange.getPreMasterSecret();
        Assert.assertEquals(48, bytes.length);
    }

    @Test
    public void toStringTest() throws Exception {
        SecureRandom random = new SecureRandom();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(ProtocolVersion.NTLS_1_1,
                random, getCertificate());
        String str = clientKeyExchange.toString();
        Assert.assertTrue(str.contains("struct {"));
        Assert.assertTrue(str.contains("encryptedPreMasterSecret ="));
        Assert.assertTrue(str.contains("} ClientKeyExchange;"));
    }

    @Test
    public void getBytesTest() throws Exception {
        SecureRandom random = new SecureRandom();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(ProtocolVersion.NTLS_1_1,
                random, getCertificate());
        byte[] bytes = clientKeyExchange.getBytes();
        Assert.assertEquals(157, bytes.length);
        Assert.assertNull(ClientKeyExchange.read(null));
    }
}
