package com.aliyun.gmsse;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public class GMSSLContextSpi extends SSLContextSpi {
    static List<CipherSuite> supportedSuites = new CopyOnWriteArrayList<CipherSuite>();
    static List<ProtocolVersion> supportedProtocols = new CopyOnWriteArrayList<ProtocolVersion>();

    static {
        // setup suites
        supportedSuites.add(CipherSuite.NTLS_SM2_WITH_SM4_SM3);

        // setup protocols
        supportedProtocols.add(ProtocolVersion.NTLS_1_1);
    }

    private X509KeyManager keyManager;
    private X509TrustManager trustManager;
    private SecureRandom random;

    private SSLSessionContext clientSessionContext;
    private SSLSessionContext serverSessionContext;
    public SSLConfiguration sslConfig;

    public GMSSLContextSpi() {
        clientSessionContext = new SessionContext();
        serverSessionContext = new SessionContext();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return new GMSSLEngine(this);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return new GMSSLEngine(this, host, port);
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return clientSessionContext;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return serverSessionContext;
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return new GMSSLServerSocketFactory(this);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return new GMSSLSocketFactory(this);
    }

    @Override
    protected void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        keyManager = null;
        trustManager = null;
        if (kms != null) {
            for (int i = 0; i < kms.length; i++) {
                if (kms[i] instanceof X509KeyManager) {
                    keyManager = (X509KeyManager) kms[i];
                    break;
                }
            }
        }

        if (tms != null) {
            for (int i = 0; i < tms.length; i++) {
                if (tms[i] instanceof X509TrustManager) {
                    if (trustManager == null) {
                        trustManager = (X509TrustManager) tms[i];
                    }
                }
            }
        }

        if (trustManager == null) {
            trustManager = defaultTrustManager();
        }

        if (sr != null) {
            this.random = sr;
        } else {
            this.random = new SecureRandom();
        }
    }

    private X509TrustManager defaultTrustManager() throws KeyManagementException {
        try {
            TrustManagerFactory fact = TrustManagerFactory.getInstance("X509", new GMProvider());
            fact.init((KeyStore) null);
            return (X509TrustManager) fact.getTrustManagers()[0];
        } catch (NoSuchAlgorithmException nsae) {
            throw new KeyManagementException(nsae.toString());
        } catch (KeyStoreException e) {
            throw new KeyManagementException(e.toString());
        }
    }

    public List<CipherSuite> getSupportedCipherSuites() {
        return supportedSuites;
    }

    public List<ProtocolVersion> getSupportedProtocolVersions() {
        return supportedProtocols;
    }

    // Get default protocols.
    List<ProtocolVersion> getDefaultProtocolVersions(boolean roleIsServer) {
        return supportedProtocols;
    }

    // Get default cipher suites.
    List<CipherSuite> getDefaultCipherSuites(boolean roleIsServer) {
        return supportedSuites;
    }

    public SecureRandom getSecureRandom() {
        return random;
    }

    public X509KeyManager getKeyManager() {
        return keyManager;
    }

    public X509TrustManager getTrustManager() {
        return trustManager;
    }
}