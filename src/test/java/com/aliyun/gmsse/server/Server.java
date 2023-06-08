package com.aliyun.gmsse.server;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.aliyun.gmsse.GMProvider;
import com.aliyun.gmsse.Helper;

public class Server {

    public SSLServerSocket buildServerSocket() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

        KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        ks.load(null, null);

        ks.setKeyEntry("sign", Helper.loadPrivateKey("sm2/server_sign.key"), new char[0], new X509Certificate[] {
            Helper.loadCertificate("sm2/server_sign.crt")
        });
        ks.setKeyEntry("enc", Helper.loadPrivateKey("sm2/server_enc.key"), new char[0], new X509Certificate[] {
            Helper.loadCertificate("sm2/server_enc.crt")
        });

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, new char[0]);

        X509Certificate cert = Helper.loadCertificate("sm2/chain-ca.crt");
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
