package com.aliyun;

import javax.net.ssl.*;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public class GMSSLSession implements SSLSession {

    private long creationTime;
    public List<CipherSuite> enabledSuites;
    public List<ProtocolVersion> enabledProtocols;
    public X509Certificate[] peerCerts;
    public CipherSuite cipherSuite;
    ProtocolVersion protocol;
    SessionContext sessionContext;
    ID sessionId;
    public String peerHost;
    public KeyManager keyManager;
    public TrustManager trustManager;
    public SecureRandom random;

    public GMSSLSession(List<CipherSuite> enabledSuites, List<ProtocolVersion> enabledProtocols) {
        this.creationTime = System.currentTimeMillis();
        this.enabledSuites = enabledSuites;
        this.enabledProtocols = enabledProtocols;
    }

    @Override
    public int getApplicationBufferSize() {
        return 0;
    }

    @Override
    public String getCipherSuite() {
        return cipherSuite.getName();
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public byte[] getId() {
        return sessionId.getId();
    }

    @Override
    public long getLastAccessedTime() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public Certificate[] getLocalCertificates() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Principal getLocalPrincipal() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getPacketBufferSize() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public String getPeerHost() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getPeerPort() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getProtocol() {
        return protocol.toString();
    }

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return sessionContext;
    }

    @Override
    public Object getValue(String name) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String[] getValueNames() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void invalidate() {
        // TODO Auto-generated method stub

    }

    @Override
    public boolean isValid() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void putValue(String name, Object value) {
        // TODO Auto-generated method stub

    }

    @Override
    public void removeValue(String name) {
        // TODO Auto-generated method stub

    }

    public static class ID {
        private final byte[] id;

        public ID(byte[] id) {
            this.id = id;
        }

        public byte[] getId() {
            return id.clone();
        }
    }
}