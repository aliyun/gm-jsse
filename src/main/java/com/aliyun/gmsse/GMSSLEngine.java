package com.aliyun.gmsse;

import java.io.IOException;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;

import com.aliyun.gmsse.protocol.ClientConnectionContext;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

public class GMSSLEngine extends SSLEngine {

    private GMSSLContextSpi context;
    private ConnectionContext connection;
    private HandshakeProtocol protocol;

    public GMSSLEngine(GMSSLContextSpi context, String host, int port) {
        super(host, port);
        this.context = context;
        this.connection = new ClientConnectionContext(context, null);
    }

    public GMSSLEngine(GMSSLContextSpi context) {
        this(context, null, -1);
    }

    @Override
    public void beginHandshake() throws SSLException {
        if (getUseClientMode()) {
            ClientHandshakeProtocol clientProtocol = new ClientHandshakeProtocol(context);
            clientProtocol.connect();
            this.protocol = clientProtocol;
        } else {
            // TODO: server side
        }
    }

    @Override
    public void closeInbound() throws SSLException {
        try {
            this.protocol.closeInbound();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Override
    public void closeOutbound() {
        try {
            this.protocol.closeOutbound();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Override
    public Runnable getDelegatedTask() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean getEnableSessionCreation() {
        return connection.sslConfig.enableSessionCreation;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(connection.sslConfig.enabledCipherSuites);
    }

    @Override
    public String[] getEnabledProtocols() {
        return ProtocolVersion.toStringArray(connection.sslConfig.enabledProtocols);
    }

    @Override
    public HandshakeStatus getHandshakeStatus() {
        return connection.getHandshakeStatus();
    }

    @Override
    public boolean getNeedClientAuth() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public SSLSession getSession() {
        return connection.session;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(context.getSupportedCipherSuites());
    }

    @Override
    public String[] getSupportedProtocols() {
        return ProtocolVersion.toStringArray(context.getSupportedProtocolVersions());
    }

    @Override
    public boolean getUseClientMode() {
        return connection.sslConfig.isClientMode;
    }

    @Override
    public boolean getWantClientAuth() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isInboundDone() {
        return connection.isInboundClosed();
    }

    @Override
    public boolean isOutboundDone() {
        return connection.isOutboundDone();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        connection.sslConfig.enableSessionCreation = flag;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        // TODO Auto-generated method stub
    }

    @Override
    public void setEnabledProtocols(String[] arg0) {
        // TODO Auto-generated method stub
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        // TODO Auto-generated method stub
    }

    @Override
    public void setUseClientMode(boolean mode) {
        connection.setUseClientMode(mode);
    }

    @Override
    public void setWantClientAuth(boolean want) {
        // TODO Auto-generated method stub
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        return unwrap(new ByteBuffer[]{src}, 0, 1, dsts, offset, length);
    }

    private SSLEngineResult unwrap(ByteBuffer[] srcs, int srcsOffset, int srcslength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) {
        if (isInboundDone()) {
            return new SSLEngineResult(Status.CLOSED, getHandshakeStatus(), 0, 0, -1);
        }
        return null;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] appData, int offset, int length, ByteBuffer netData) throws SSLException {
        return wrap(appData, offset, length, new ByteBuffer[]{ netData }, 0, 1);
    }

    private SSLEngineResult wrap(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) {
        return null;
    }

}
