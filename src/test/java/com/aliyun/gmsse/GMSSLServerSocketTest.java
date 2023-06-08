package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLServerSocket;

public class GMSSLServerSocketTest {

    public GMSSLContextSpi getSSLContext() throws NoSuchAlgorithmException, KeyManagementException {
        return new GMSSLContextSpi();
    }

    @Test
    public void enableSessionCreationTest() throws Exception {
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(getSSLContext());
        SSLServerSocket ss = (SSLServerSocket)ssf.createServerSocket(8080);

        Assert.assertTrue(ss.getEnableSessionCreation());
        ss.setEnableSessionCreation(false);
        Assert.assertFalse(ss.getEnableSessionCreation());
        ss.close();
    }

    @Test
    public void getSupportedCipherSuitesTest() throws Exception {
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(getSSLContext());
        SSLServerSocket ss = (SSLServerSocket)ssf.createServerSocket(8080);

        Assert.assertArrayEquals(new String[] {"ECC-SM2-WITH-SM4-SM3"}, ss.getSupportedCipherSuites());
        ss.close();
    }

    @Test
    public void getSupportedProtocolsTest() throws Exception {
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(getSSLContext());
        SSLServerSocket ss = (SSLServerSocket)ssf.createServerSocket(8080);

        Assert.assertArrayEquals(new String[] {"NTLSv1.1"}, ss.getSupportedProtocols());
        ss.close();
    }

    @Test
    public void enabledCipherSuitesTest() throws Exception {
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(getSSLContext());
        SSLServerSocket ss = (SSLServerSocket)ssf.createServerSocket(8080);

        Assert.assertArrayEquals(new String[] {"ECC-SM2-WITH-SM4-SM3"}, ss.getEnabledCipherSuites());
        ss.setEnabledCipherSuites(new String[] {});
        Assert.assertArrayEquals(new String[] {}, ss.getEnabledCipherSuites());
        ss.close();
    }

    @Test
    public void enabledProtocolsTest() throws Exception {
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(getSSLContext());
        SSLServerSocket ss = (SSLServerSocket)ssf.createServerSocket(8080);

        Assert.assertArrayEquals(new String[] {"NTLSv1.1"}, ss.getEnabledProtocols());
        ss.setEnabledProtocols(new String[] {});
        Assert.assertArrayEquals(new String[] {}, ss.getEnabledProtocols());
        ss.close();
    }

    @Test
    public void needClientAuthTest() throws Exception {
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(getSSLContext());
        SSLServerSocket ss = (SSLServerSocket)ssf.createServerSocket(8080);

        Assert.assertFalse(ss.getNeedClientAuth());
        ss.setNeedClientAuth(true);
        Assert.assertTrue(ss.getNeedClientAuth());

        ss.setNeedClientAuth(false);
        Assert.assertFalse(ss.getNeedClientAuth());
        ss.close();
    }

    @Test
    public void wantClientAuthTest() throws Exception {
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(getSSLContext());
        SSLServerSocket ss = (SSLServerSocket)ssf.createServerSocket(8080);

        Assert.assertFalse(ss.getWantClientAuth());
        ss.setWantClientAuth(true);
        Assert.assertTrue(ss.getWantClientAuth());
        ss.setWantClientAuth(false);
        Assert.assertFalse(ss.getWantClientAuth());
        ss.close();
    }

    @Test
    public void useClientModeTest() throws Exception {
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(getSSLContext());
        SSLServerSocket ss = (SSLServerSocket)ssf.createServerSocket(8080);

        Assert.assertFalse(ss.getUseClientMode());
        ss.setUseClientMode(true);
        Assert.assertTrue(ss.getUseClientMode());
        ss.close();
    }
}
