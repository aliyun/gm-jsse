package com.aliyun.gmsse.crypto;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class CryptoTest {

    SecureRandom random = new SecureRandom();

    public X509Certificate loadX509Certificate(String path) throws CertificateException, IOException {
        InputStream is = this.getClass().getClassLoader().getResourceAsStream(path);
        BouncyCastleProvider bc = new BouncyCastleProvider();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        is.close();
        return cert;
    }

    public PrivateKey loadPrivateKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream is = this.getClass().getClassLoader().getResourceAsStream(path);
        InputStreamReader inputStreamReader = new InputStreamReader(is);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        StringBuilder sb = new StringBuilder();
        String line = null;
            while ((line = bufferedReader.readLine()) != null){
            if (line.startsWith("-")){
                continue;
            }
            sb.append(line).append("\n");
        }
        String ecKey = sb.toString().replaceAll("\\r\\n|\\r|\\n", "");
        Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] keyByte = base64Decoder.decode(ecKey.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec eks2 = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PrivateKey privateKey = keyFactory.generatePrivate(eks2);
        return privateKey;
    }

    @Test
    public void testEncrypt() throws Exception{
        X509Certificate cert = loadX509Certificate("sm2/server_enc.crt");
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        ba.write(1);
        ba.write(1);
        ba.write(random.generateSeed(46));
        byte[] preMasterSecret = ba.toByteArray();
        byte[] r = Crypto.encrypt((BCECPublicKey)cert.getPublicKey(), preMasterSecret);
        Assert.assertEquals(155, r.length);
    }

    @Test
    @Ignore
    public void testEncryptAndDecrypt() throws Exception{
        X509Certificate cert = loadX509Certificate("sm2/server_enc.crt");
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        ba.write(1);
        ba.write(1);
        ba.write(random.generateSeed(46));
        byte[] preMasterSecret = ba.toByteArray();
        byte[] encryptedPreMasterSecret = Crypto.encrypt((BCECPublicKey)cert.getPublicKey(), preMasterSecret);

        PrivateKey key = loadPrivateKey("sm2/server_enc.key");

        byte[] decryptedPreMasterSecret = Crypto.decrypt((BCECPrivateKey)key, encryptedPreMasterSecret);
        Assert.assertArrayEquals(preMasterSecret, decryptedPreMasterSecret);
    }
}
