package com.aliyun.gmsse.server;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import com.aliyun.gmsse.GMProvider;

public class ServerTest {

    @Test
    public void testServer() throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, UnrecoverableKeyException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);
        BouncyCastleProvider bc = new BouncyCastleProvider();

        // TODO: 设置国密双证书、CA 证书
        KeyStore ks = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        FileInputStream is = new FileInputStream(this.getClass().getClassLoader().getResource("WoTrus-SM2.crt").getFile());
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        ks.load(null, "password".toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ks, "password".toCharArray());

        sc.init(keyManagerFactory.getKeyManagers(), null, null);
        SSLServerSocketFactory ssf = sc.getServerSocketFactory();
        SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(8443);
        ss.setNeedClientAuth(true);
        // ss.setEnabledProtocols(new String[] { "TLSv1.2" });
        SSLSocket socket = (SSLSocket) ss.accept();
        socket.startHandshake();
        // InputStream and OutputStream Stuff
        socket.getOutputStream().write("Hello".getBytes());
        socket.getOutputStream().flush();
        socket.close();
    }

}
