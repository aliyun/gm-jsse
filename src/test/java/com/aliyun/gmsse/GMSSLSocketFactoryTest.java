package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;

import java.net.InetAddress;
import java.net.Socket;

public class GMSSLSocketFactoryTest {

    @Test
    public void nullTest() throws Exception{
        GMSSLSocketFactory mySSLSocketFactory = new GMSSLSocketFactory(null);

        Assert.assertNull(mySSLSocketFactory.getDefaultCipherSuites());
        Assert.assertNull(mySSLSocketFactory.getSupportedCipherSuites());
        Assert.assertNull(mySSLSocketFactory.createSocket("null", 80, null, 80));
    }

    @Test
    public void createSocketTest() throws Exception {
        GMSSLContextSpi context = new GMSSLContextSpi();
        GMSSLSocketFactory mySSLSocketFactory = new GMSSLSocketFactory(context);
        Socket socket = mySSLSocketFactory.createSocket(null, "test", 80, false);
        Assert.assertNotNull(socket);

        socket = mySSLSocketFactory.createSocket("www.aliyun.com", 80);
        Assert.assertNotNull(socket);

        InetAddress inet = InetAddress.getByName("www.aliyun.com");
        socket = mySSLSocketFactory.createSocket(inet, 80);
        Assert.assertNotNull(socket);
    }
}
