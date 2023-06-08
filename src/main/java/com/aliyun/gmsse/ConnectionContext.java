package com.aliyun.gmsse;

import java.io.IOException;

public abstract class ConnectionContext {

    protected GMSSLContextSpi sslContext;
    public SSLConfiguration sslConfig;
    protected GMSSLSocket socket;
    protected final GMSSLSession session;
    public boolean isNegotiated = false;

    public ConnectionContext(GMSSLContextSpi context, GMSSLSocket socket, SSLConfiguration sslConfig) {
        this.sslContext = context;
        this.sslConfig = sslConfig;
        this.socket = socket;
        this.session = new GMSSLSession();
    }

    public abstract void kickstart() throws IOException;
}
