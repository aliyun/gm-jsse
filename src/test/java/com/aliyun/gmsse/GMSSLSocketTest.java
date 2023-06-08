package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.Field;


public class GMSSLSocketTest {

    @Test
    public void getEnabledCipherSuitesTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket(new GMSSLContextSpi(), "www.aliyun.com", 80);
        String[] strings = sslSocket.getEnabledCipherSuites();
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", strings[0]);
        sslSocket.close();
    }

    @Test
    public void getTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket(new GMSSLContextSpi(), "www.aliyun.com", 80);

        sslSocket.setEnableSessionCreation(false);
        Assert.assertFalse(sslSocket.getEnableSessionCreation());

        String[] strings = sslSocket.getEnabledProtocols();
        Assert.assertEquals("NTLSv1.1", strings[0]);

        sslSocket.setNeedClientAuth(false);
        Assert.assertFalse(sslSocket.getNeedClientAuth());
        sslSocket.setNeedClientAuth(true);
        Assert.assertTrue(sslSocket.getNeedClientAuth());

        Assert.assertNotNull(sslSocket.getSession());

        strings = sslSocket.getSupportedCipherSuites();
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", strings[0]);

        strings = sslSocket.getSupportedProtocols();
        Assert.assertEquals("NTLSv1.1", strings[0]);

        sslSocket.setUseClientMode(true);
        Assert.assertTrue(sslSocket.getUseClientMode());

        Assert.assertFalse(sslSocket.getWantClientAuth());
        sslSocket.setWantClientAuth(true);
        Assert.assertTrue(sslSocket.getWantClientAuth());

        sslSocket.close();
    }

    @Test
    public void setEnabledProtocolsTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket(new GMSSLContextSpi(), "www.aliyun.com", 80);
        try {
            sslSocket.setEnabledProtocols(null);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertNotNull(e);
        }

        String[] strings = new String[0];
        try {
            sslSocket.setEnabledProtocols(strings);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertNotNull(e);
        }

        strings = new String[] { "NTLSv1.1", "test" };
        try {
            sslSocket.setEnabledProtocols(strings);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertEquals("unsupported protocol: test", e.getMessage());
        }

        sslSocket.close();
    }

    @Test
    public void setEnabledCipherSuitesTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket(new GMSSLContextSpi(), "www.aliyun.com", 80);

        try {
            sslSocket.setEnabledCipherSuites(null);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertNotNull(e);
        }

        String[] strings = new String[0];
        try {
            sslSocket.setEnabledCipherSuites(strings);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertNotNull(e);
        }

        strings = new String[] { "ECC-SM2-WITH-SM4-SM3", "test" };
        try {
            sslSocket.setEnabledCipherSuites(strings);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertEquals("unsupported suite: test", e.getMessage());
        }

        strings = new String[] { "ECC-SM2-WITH-SM4-SM3", "ECC-SM2-WITH-SM4-SM3" };
        sslSocket.setEnabledCipherSuites(strings);
        Field connection = sslSocket.getClass().getDeclaredField("connection");
        connection.setAccessible(true);
        connection.get(sslSocket);
        ConnectionContext cc = (ConnectionContext) connection.get(sslSocket);
        Assert.assertEquals(CipherSuite.NTLS_SM2_WITH_SM4_SM3, cc.sslConfig.enabledCipherSuites.get(0));
        sslSocket.close();
    }

    @Test
    public void getOutputStreamTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(new GMSSLContextSpi(), "www.aliyun.com", 80);
        Assert.assertNotNull(gmsslSocket.getOutputStream());
        gmsslSocket.close();
    }
}
