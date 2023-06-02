package com.aliyun.gmsse.crypto;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

public class CryptoTest {
    @Test
    public void testEncrypt() throws Exception{
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("sm2/server_enc.crt");
        BouncyCastleProvider bc = new BouncyCastleProvider();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        byte[] r = Crypto.encrypt((BCECPublicKey)cert.getPublicKey(), "premasterkey".getBytes());
        Assert.assertEquals(118, r.length);
    }
}
