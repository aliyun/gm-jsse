package com.aliyun.gmsse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class GMSSLSocketFactoryTest {

    @Test
    public void createSocketTest() throws Exception {
        GMSSLContextSpi context = new GMSSLContextSpi();
        GMSSLSocketFactory mySSLSocketFactory = new GMSSLSocketFactory(context);
        
        Socket socket = mySSLSocketFactory.createSocket(new Socket("www.aliyun.com", 80), "www.aliyun.com", 80, false);
        Assert.assertNotNull(socket);

        socket = mySSLSocketFactory.createSocket("www.aliyun.com", 80);
        Assert.assertNotNull(socket);

        InetAddress inet = InetAddress.getByName("www.aliyun.com");
        socket = mySSLSocketFactory.createSocket(inet, 80);
        Assert.assertNotNull(socket);
    }

    private SSLSocketFactory createSSF() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

        BouncyCastleProvider bc = new BouncyCastleProvider();
        KeyStore ks = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("WoTrus-SM2.crt");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        ks.load(null, null);
        ks.setCertificateEntry("gmca", cert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);
        sc.init(null, tmf.getTrustManagers(), null);
        SSLSocketFactory mySSLSocketFactory = sc.getSocketFactory();
        return mySSLSocketFactory;
    }

    @Test
    public void createSocketTest2() throws UnknownHostException, IOException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        Socket socket = createSSF().createSocket("sm2only.ovssl.cn", 443, null, 0);
        Assert.assertNotNull(socket);
        socket.setTcpNoDelay(true);
        Assert.assertTrue(socket.getTcpNoDelay());
        OutputStream os = socket.getOutputStream();
        os.write("hello".getBytes());
        os.flush();
        socket.close();
    }

    @Test
    public void createSocketTest3() throws UnknownHostException, IOException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        InetAddress address = InetAddress.getByName("sm2only.ovssl.cn");
        Socket socket = createSSF().createSocket(address, 443, null, 0);
        Assert.assertNotNull(socket);
        socket.close();
    }
}
