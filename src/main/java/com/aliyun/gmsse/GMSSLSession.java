package com.aliyun.gmsse;

import javax.net.ssl.*;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicLong;

public class GMSSLSession implements SSLSession {

    private long creationTime;
    // public List<CipherSuite> enabledSuites;
    // public List<ProtocolVersion> enabledProtocols;
    public X509Certificate[] peerCerts;
    public CipherSuite cipherSuite;
    ProtocolVersion protocol;
    SessionContext sessionContext;
    public ID sessionId;
    public String peerHost;
    public int peerPort;
    public boolean peerVerified;
    protected final AtomicLong lastAccessedTime;

    public GMSSLSession() {
        this.creationTime = System.currentTimeMillis();
        this.lastAccessedTime = new AtomicLong(creationTime);
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
        return lastAccessedTime.get();
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
        return peerHost;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
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
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return peerCerts;
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

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        // TODO Auto-generated method stub
        return null;
    }
}