package com.aliyun.gmsse;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public class GMSSLContextSpi extends SSLContextSpi {

    private KeyManager keyManager;
    private TrustManager trustManager;
    private SecureRandom random;
    private SSLSessionContext clientSessionContext;

    public GMSSLContextSpi() {
        clientSessionContext = new SessionContext();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return null;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return null;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return clientSessionContext;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return null;
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return null;
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return new GMSSLSocketFactory(keyManager, trustManager, random, clientSessionContext);
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

        if (sr != null) {
            this.random = sr;
        } else {
            this.random = new SecureRandom();
        }
    }

}