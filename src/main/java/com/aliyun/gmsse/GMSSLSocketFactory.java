package com.aliyun.gmsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;

import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public class GMSSLSocketFactory extends SSLSocketFactory {

    private final X509TrustManager trustManager;
    private final X509KeyManager keyManager;
    private final SecureRandom random;
    private final SSLSessionContext sessionContext;

    public GMSSLSocketFactory(X509KeyManager keyManager, X509TrustManager trustManager, SecureRandom random,
            SSLSessionContext sessionContext) {
        this.trustManager = trustManager;
        this.keyManager = keyManager;
        this.random = random;
        this.sessionContext = sessionContext;
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return setup(new GMSSLSocket(socket, host, port, autoClose));
    }

    private Socket setup(GMSSLSocket socket) {
        socket.session.keyManager = keyManager;
        socket.session.trustManager = trustManager;
        socket.session.random = random;
        return socket;
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
        GMSSLSocket socket = new GMSSLSocket(host, port);
        socket.session.keyManager = keyManager;
        socket.session.trustManager = trustManager;
        socket.session.random = random;
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return new GMSSLSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return null;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return null;
    }

}