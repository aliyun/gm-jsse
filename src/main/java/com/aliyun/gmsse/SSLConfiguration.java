package com.aliyun.gmsse;

import java.util.List;

public class SSLConfiguration {

    public SSLConfiguration(GMSSLContextSpi sslContext, boolean isClientMode) {
        this.enabledProtocols = sslContext.getDefaultProtocolVersions(!isClientMode);
        this.enabledCipherSuites = sslContext.getDefaultCipherSuites(!isClientMode);
        // this.clientAuthType = ClientAuthType.CLIENT_AUTH_NONE;
    }

    public List<ProtocolVersion> enabledProtocols;
    public List<CipherSuite> enabledCipherSuites;
    public boolean enableSessionCreation;

}
