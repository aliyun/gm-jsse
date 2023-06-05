package com.aliyun.gmsse.server;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.aliyun.gmsse.GMProvider;

public class Server {

    public static X509Certificate loadCertificate(String path) throws KeyStoreException, CertificateException, FileNotFoundException {
        BouncyCastleProvider bc = new BouncyCastleProvider();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        InputStream is = Server.class.getClassLoader().getResourceAsStream(path);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        return cert;
    }

    public static PrivateKey loadPrivateKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream is = Server.class.getClassLoader().getResourceAsStream(path);
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

    public SSLServerSocket buildServerSocket() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

        KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        ks.load(null, null);

        ks.setKeyEntry("sign", loadPrivateKey("sm2/server_sign.key"), new char[0], new X509Certificate[] {
            loadCertificate("sm2/server_sign.crt")
        });
        ks.setKeyEntry("enc", loadPrivateKey("sm2/server_enc.key"), new char[0], new X509Certificate[] {
            loadCertificate("sm2/server_enc.crt")
        });

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, new char[0]);

        X509Certificate cert = loadCertificate("sm2/chain-ca.crt");
        ks.setCertificateEntry("ca", cert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);

        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        SSLServerSocketFactory ssf = sc.getServerSocketFactory();
        SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(8443);
        ss.setNeedClientAuth(true);
        // ss.setEnabledProtocols(new String[] { "TLSv1.2" });
        return ss;
    }

}
