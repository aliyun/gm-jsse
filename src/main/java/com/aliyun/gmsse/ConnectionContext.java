package com.aliyun.gmsse;

import java.io.IOException;

import javax.net.ssl.SSLEngineResult.HandshakeStatus;

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

    public void setUseClientMode(boolean mode) {
        sslConfig.isClientMode = mode;
    }

    public HandshakeStatus getHandshakeStatus() {
        // if (!outputRecord.isEmpty()) {
        // // If no handshaking, special case to wrap alters or
        // // post-handshake messages.
        // return HandshakeStatus.NEED_WRAP;
        // } else if (isOutboundClosed() && isInboundClosed()) {
        // return HandshakeStatus.NOT_HANDSHAKING;
        // } else if (handshakeContext != null) {
        // if (!handshakeContext.delegatedActions.isEmpty()) {
        // return HandshakeStatus.NEED_TASK;
        // } else if (!isInboundClosed()) {
        // //JDK8 NEED_UNWRAP returnned for NEED_UNWRAP_AGAIN status
        // // needUnwrapAgain should be used to determine NEED_UNWRAP_AGAIN
        // return HandshakeStatus.NEED_UNWRAP;
        // } else if (!isOutboundClosed()) {
        // // Special case that the inbound was closed, but outbound open.
        // return HandshakeStatus.NEED_WRAP;
        // }
        // } else if (isOutboundClosed() && !isInboundClosed()) {
        // // Special case that the outbound was closed, but inbound open.
        // return HandshakeStatus.NEED_UNWRAP;
        // } else if (!isOutboundClosed() && isInboundClosed()) {
        // // Special case that the inbound was closed, but outbound open.
        // return HandshakeStatus.NEED_WRAP;
        // }

        return HandshakeStatus.NOT_HANDSHAKING;
    }

    public boolean isInboundClosed() {
        return false;
    }

    public boolean isOutboundDone() {
        return false;
    }
}
