package com.aliyun.gmsse;

import java.security.cert.X509Certificate;

import com.aliyun.gmsse.GMSSLSession.ID;

public class ConnectionContext {

    private GMSSLContextSpi sslContext;

    public ConnectionContext(GMSSLContextSpi context, boolean isClientMode) {
        this.sslContext = context;
        this.sslConfig = new SSLConfiguration(context, isClientMode);
        this.session = new GMSSLSession();
    }

    public SSLConfiguration sslConfig;
    public ID sessionId;
    public int peerPort;
    public boolean peerVerified;
    public String peerHost;
    public CipherSuite cipherSuite;
    public X509Certificate[] peerCerts;
    public GMSSLSession session;
    public boolean isNegotiated = false;

}
