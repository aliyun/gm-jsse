package com.aliyun;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;

public class GMSSLContextSpiTest {

    @Test
    public void nullTest() {
        GMSSLContextSpi mySSLContextSpi = new GMSSLContextSpi();
        Assert.assertNull(mySSLContextSpi.engineCreateSSLEngine());
        Assert.assertNull(mySSLContextSpi.engineCreateSSLEngine(null, 90));
        Assert.assertNull(mySSLContextSpi.engineGetServerSessionContext());
        Assert.assertNull(mySSLContextSpi.engineGetServerSocketFactory());
        Assert.assertNotNull(mySSLContextSpi.engineGetSocketFactory());
        Assert.assertNotNull(mySSLContextSpi.engineGetClientSessionContext());
    }

    @Test
    public void engineInitTest() throws Exception {
        GMSSLContextSpi mySSLContextSpi = Mockito.spy(new GMSSLContextSpi());
        mySSLContextSpi.engineInit(null, null, null);
        Mockito.verify(mySSLContextSpi, Mockito.times(1)).engineInit(null, null, null);

        KeyManager[] kms = new KeyManager[2];
        kms[0] = new KeyManagerImpl();
        kms[1] = Mockito.mock(X509KeyManager.class);

        TrustManager[] tms = new TrustManager[3];
        tms[0] = new TrustManagerImpl();
        tms[1] = Mockito.mock(X509TrustManager.class);
        tms[2] = Mockito.mock(X509TrustManager.class);

        SecureRandom secureRandom = Mockito.mock(SecureRandom.class);
        mySSLContextSpi.engineInit(kms, tms, secureRandom);
        Mockito.verify(mySSLContextSpi, Mockito.times(1)).engineInit(kms, tms, secureRandom);
    }

    class KeyManagerImpl implements KeyManager {
    }

    class TrustManagerImpl implements TrustManager {
    }
}
