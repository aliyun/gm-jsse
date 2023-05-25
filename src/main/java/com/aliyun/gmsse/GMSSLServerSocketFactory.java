package com.aliyun.gmsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import javax.net.ssl.SSLServerSocketFactory;

public class GMSSLServerSocketFactory extends SSLServerSocketFactory {

    private static final int DEFAULT_BACKLOG = 50;

    private final GMSSLContextSpi context;

    public GMSSLServerSocketFactory(GMSSLContextSpi context) {
        this.context = context;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return CipherSuite.namesOf(context.getDefaultCipherSuites(true));
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(context.getSupportedCipherSuites());
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return new GMSSLServerSocket(context, port, DEFAULT_BACKLOG);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return new GMSSLServerSocket(context, port, backlog);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        return new GMSSLServerSocket(context, port, backlog, ifAddress);
    }

}
