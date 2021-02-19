package com.aliyun.gmsse;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

public class GMX509TrustManagerFactory extends TrustManagerFactorySpi {
    /**
     * The location of the system key store, containing the CA certs.
     */
    private static final String CA_CERTS = Util.getProperty("java.home") + Util.getProperty("file.separator") + "lib"
            + Util.getProperty("file.separator") + "security" + Util.getProperty("file.separator") + "cacerts";

    private Manager current;

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        if (current == null) {
            throw new IllegalStateException("not initialized");
        }
        return new TrustManager[] { current };
    }

    @Override
    protected void engineInit(KeyStore store) throws KeyStoreException {
        // TODO Auto-generated method stub
        if (store == null) {
            String s = Util.getProperty("javax.net.ssl.trustStoreType");
            if (s == null) {
                s = KeyStore.getDefaultType();
            }
            store = KeyStore.getInstance(s);
            try {
                s = Util.getProperty("javax.net.ssl.trustStore");
                FileInputStream in = null;
                if (s == null) {
                    in = new FileInputStream(CA_CERTS);
                } else {
                    in = new FileInputStream(s);
                }
                String p = Util.getProperty("javax.net.ssl.trustStorePassword");
                store.load(in, p != null ? p.toCharArray() : null);
            } catch (IOException ioe) {
                throw new KeyStoreException(ioe.toString());
            } catch (CertificateException ce) {
                throw new KeyStoreException(ce.toString());
            } catch (NoSuchAlgorithmException nsae) {
                throw new KeyStoreException(nsae.toString());
            }
        }

        LinkedList<Certificate> l = new LinkedList<Certificate>();
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            String alias = (String) aliases.nextElement();
            if (!store.isCertificateEntry(alias))
                continue;
            Certificate c = store.getCertificate(alias);
            if (!(c instanceof X509Certificate))
                continue;
            l.add(c);
        }

        current = this.new Manager((X509Certificate[]) l.toArray(new X509Certificate[l.size()]));
    }

    @Override
    protected void engineInit(ManagerFactoryParameters params) throws InvalidAlgorithmParameterException {
    }

    private class Manager implements X509TrustManager {
        private final X509Certificate[] trusted;

        Manager(X509Certificate[] trusted) {
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
}
