package com.aliyun;

import com.aliyun.gmsse.GMSSLSocketFactory;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.net.InetAddress;
import java.net.Socket;

public class GMSSLSocketFactoryTest {

    @Test
    public void nullTest() throws Exception{
        GMSSLSocketFactory mySSLSocketFactory = new GMSSLSocketFactory(
                null, null, null, null);

        Assert.assertNull(mySSLSocketFactory.getDefaultCipherSuites());
        Assert.assertNull(mySSLSocketFactory.getSupportedCipherSuites());

        Assert.assertNull(mySSLSocketFactory.createSocket("null", 80, null, 80));
        InetAddress address = Mockito.mock(InetAddress.class);
        Assert.assertNull(mySSLSocketFactory.createSocket(address, 80, address, 80));
    }

    @Test
    public void createSocketTest() throws Exception{
        GMSSLSocketFactory mySSLSocketFactory = new GMSSLSocketFactory(
                null, null, null, null);
        Socket socket = mySSLSocketFactory.createSocket(null, "test", 80, false);
        Assert.assertNotNull(socket);

        socket = mySSLSocketFactory.createSocket("www.aliyun.com", 80);
        Assert.assertNotNull(socket);

        InetAddress inet = InetAddress.getByName("www.aliyun.com");
        socket = mySSLSocketFactory.createSocket(inet, 80);
        Assert.assertNotNull(socket);
    }
}
