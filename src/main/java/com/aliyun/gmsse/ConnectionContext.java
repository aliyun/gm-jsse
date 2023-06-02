package com.aliyun.gmsse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.aliyun.gmsse.record.Handshake;

public abstract class ConnectionContext {

    protected GMSSLContextSpi sslContext;
    public SSLConfiguration sslConfig;
    protected SecurityParameters securityParameters = new SecurityParameters();
    protected List<Handshake> handshakes = new ArrayList<Handshake>();
    protected GMSSLSocket socket;
    protected GMSSLSession session = new GMSSLSession();
    public boolean isNegotiated = false;

    public ConnectionContext(GMSSLContextSpi context, GMSSLSocket socket, SSLConfiguration sslConfig) {
        this.sslContext = context;
        this.sslConfig = sslConfig;
        this.socket = socket;
        this.session = new GMSSLSession();
    }

    public abstract void kickstart() throws IOException;
}
