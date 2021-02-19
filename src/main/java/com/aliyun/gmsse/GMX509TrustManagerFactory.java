package com.aliyun.gmsse;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

public class GMX509TrustManagerFactory extends TrustManagerFactorySpi {
    /**
     * The location of the system key store, containing the CA certs.
     */
    private static final String CA_CERTS = Util.getProperty("java.home") + Util.getProperty("file.separator") + "lib"
            + Util.getProperty("file.separator") + "security" + Util.getProperty("file.separator") + "cacerts";

    private GMX509TrustManager current;

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        if (current == null) {
            throw new IllegalStateException("not initialized");
        }
        return new TrustManager[] { current };
    }

    @Override
    protected void engineInit(KeyStore store) throws KeyStoreException {
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

        current = new GMX509TrustManager((X509Certificate[]) l.toArray(new X509Certificate[l.size()]));
    }

    @Override
    protected void engineInit(ManagerFactoryParameters params) throws InvalidAlgorithmParameterException {
    }
}
