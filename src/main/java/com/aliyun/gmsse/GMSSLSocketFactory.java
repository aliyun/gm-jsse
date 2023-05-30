package com.aliyun.gmsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

public class GMSSLSocketFactory extends SSLSocketFactory {

    private final GMSSLContextSpi context;

    public GMSSLSocketFactory(GMSSLContextSpi context) {
        this.context = context;
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return new GMSSLSocket(context, socket, host, port, autoClose);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return null;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return null;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return new GMSSLSocket(context, host, port);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return new GMSSLSocket(context, host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return new GMSSLSocket(context, host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return new GMSSLSocket(context, address, port, localAddress, localPort);
    }

}