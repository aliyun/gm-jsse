package com.aliyun.gmsse;

import javax.net.ssl.X509TrustManager;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class GMX509TrustManager implements X509TrustManager {
    private final X509Certificate[] trusted;

    GMX509TrustManager(X509Certificate[] trusted) {
        this.trusted = trusted;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        if (trusted == null) {
            return new X509Certificate[0];
        }
        return (X509Certificate[]) trusted.clone();
    }

    private void checkTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // NOTE: this is not a full-featured path validation algorithm.
        //
        // Step 0: check if the target is valid now.
        int start = 1; // 1;
        chain[start].checkValidity();

        // Step 1: verify that the chain is complete and valid.
        for (int i = start + 1; i < chain.length; i++) {
            chain[i].checkValidity();
            try {
                chain[i - 1].verify(chain[i].getPublicKey());
            } catch (NoSuchAlgorithmException nsae) {
                throw new CertificateException(nsae.toString());
            } catch (NoSuchProviderException nspe) {
                throw new CertificateException(nspe.toString());
            } catch (InvalidKeyException ike) {
                throw new CertificateException(ike.toString());
            } catch (SignatureException se) {
                throw new CertificateException(se.toString());
            }
        }

        // Step 2: verify that the root of the chain was issued by a trust anchor.
        if (trusted == null || trusted.length == 0)
            throw new CertificateException("no trust anchors");

        for (int i = 0; i < trusted.length; i++) {
            try {
                trusted[i].checkValidity();
                chain[chain.length - 1].verify(trusted[i].getPublicKey());
                return;
            } catch (Exception e) {
            }
        }

        throw new CertificateException();
    }
}
