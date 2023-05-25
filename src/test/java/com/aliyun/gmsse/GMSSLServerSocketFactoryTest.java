package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;

import java.net.InetAddress;
import java.net.ServerSocket;

public class GMSSLServerSocketFactoryTest {

    @Test
    public void createServerSocketTest() throws Exception {
        GMSSLContextSpi context = new GMSSLContextSpi();
        GMSSLServerSocketFactory ssf = new GMSSLServerSocketFactory(context);

        Assert.assertArrayEquals(new String[]{"ECC-SM2-WITH-SM4-SM3"}, ssf.getDefaultCipherSuites());
        Assert.assertArrayEquals(new String[]{"ECC-SM2-WITH-SM4-SM3"}, ssf.getSupportedCipherSuites());

        ServerSocket socket = ssf.createServerSocket(8080);
        Assert.assertNotNull(socket);
        socket.close();

        socket = ssf.createServerSocket(8080, 50);
        Assert.assertNotNull(socket);
        socket.close();

        InetAddress inet = InetAddress.getByName(null);
        socket = ssf.createServerSocket(8080, 80, inet);
        Assert.assertNotNull(socket);
        socket.close();
    }

}
