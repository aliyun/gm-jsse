package com.aliyun.gmsse;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLServerSocket;

public class GMSSLServerSocket extends SSLServerSocket {

    private final GMSSLContextSpi context;
    private SSLConfiguration sslConfig;

    public GMSSLServerSocket(GMSSLContextSpi context, int port, int backlog) throws IOException {
        super(port, backlog);
        this.context = context;
        this.sslConfig = new SSLConfiguration(context, false);
    }

    public GMSSLServerSocket(GMSSLContextSpi context, int port, int backlog, InetAddress ifAddress) throws IOException {
        super(port, backlog, ifAddress);
        this.context = context;
        this.sslConfig = new SSLConfiguration(context, false);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslConfig.enableSessionCreation;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(sslConfig.enabledCipherSuites);
    }

    @Override
    public String[] getEnabledProtocols() {
        return ProtocolVersion.toStringArray(sslConfig.enabledProtocols);
    }

    @Override
    public boolean getNeedClientAuth() {
        return (sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        List<CipherSuite> list = Arrays.asList(CipherSuite.NTLS_SM2_WITH_SM4_SM3);
        String[] suitesNames = new String[list.size()];
        int i = 0;
        for (CipherSuite cs : list) {
            suitesNames[i++] = cs.getName();
        }

        return suitesNames;
    }

    @Override
    public String[] getSupportedProtocols() {
        List<ProtocolVersion> list = Arrays.asList(ProtocolVersion.NTLS_1_1);
        String[] protocolNames = new String[list.size()];
        int i = 0;
        for (ProtocolVersion pv : list) {
            protocolNames[i++] = pv.getName();
        }

        return protocolNames;
    }

    @Override
    public boolean getUseClientMode() {
        return sslConfig.isClientMode;
    }

    @Override
    public boolean getWantClientAuth() {
        return (sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED);
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslConfig.enableSessionCreation = flag;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslConfig.enabledCipherSuites = CipherSuite.validValuesOf(suites);
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslConfig.enabledProtocols = ProtocolVersion.namesOf(protocols);
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslConfig.clientAuthType = (need ? ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE);
    }

    @Override
    public void setUseClientMode(boolean useClientMode) {
        sslConfig.isClientMode = useClientMode;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslConfig.clientAuthType =
                (want ? ClientAuthType.CLIENT_AUTH_REQUESTED :
                        ClientAuthType.CLIENT_AUTH_NONE);
    }

    @Override
    public synchronized Socket accept() throws IOException {
        Socket socket = new GMSSLSocket(context, sslConfig);
        implAccept(socket);
        return socket;
    }
}
