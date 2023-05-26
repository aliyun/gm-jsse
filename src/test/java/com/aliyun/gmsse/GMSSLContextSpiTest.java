package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import javax.net.ssl.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.SecureRandom;

public class GMSSLContextSpiTest {

    @Test
    public void nullTest() throws Exception {
        GMSSLContextSpi mySSLContextSpi = new GMSSLContextSpi();
        Method engineCreateSSLEngine = GMSSLContextSpi.class.getDeclaredMethod("engineCreateSSLEngine");
        engineCreateSSLEngine.setAccessible(true);
        Assert.assertNull(engineCreateSSLEngine.invoke(mySSLContextSpi));

        Method engineCreateSSLEngineMethod = GMSSLContextSpi.class.getDeclaredMethod("engineCreateSSLEngine", String.class, int.class);
        engineCreateSSLEngineMethod.setAccessible(true);
        Assert.assertNull(engineCreateSSLEngineMethod.invoke(mySSLContextSpi, null, 0));

        Method engineGetServerSessionContext = GMSSLContextSpi.class.getDeclaredMethod("engineGetServerSessionContext");
        engineGetServerSessionContext.setAccessible(true);
        Assert.assertNull(engineGetServerSessionContext.invoke(mySSLContextSpi));

        Method engineGetServerSocketFactory = GMSSLContextSpi.class.getDeclaredMethod("engineGetServerSocketFactory");
        engineGetServerSocketFactory.setAccessible(true);
        Assert.assertNull(engineGetServerSocketFactory.invoke(mySSLContextSpi));

        Method engineGetSocketFactory = GMSSLContextSpi.class.getDeclaredMethod("engineGetSocketFactory");
        engineGetSocketFactory.setAccessible(true);
        Assert.assertTrue(engineGetSocketFactory.invoke(mySSLContextSpi) instanceof GMSSLSocketFactory);

        Method engineGetClientSessionContext = GMSSLContextSpi.class.getDeclaredMethod("engineGetClientSessionContext");
        engineGetClientSessionContext.setAccessible(true);
        Assert.assertTrue(engineGetClientSessionContext.invoke(mySSLContextSpi) instanceof SSLSessionContext);
    }

    @Test
    public void engineInitTest() throws Exception {
        GMSSLContextSpi mySSLContextSpi = Mockito.spy(new GMSSLContextSpi());
        Method engineInitMethod = GMSSLContextSpi.class.getDeclaredMethod("engineInit",
                KeyManager[].class, TrustManager[].class, SecureRandom.class);
        engineInitMethod.setAccessible(true);
        engineInitMethod.invoke(mySSLContextSpi, null, null, null);
        Field random = GMSSLContextSpi.class.getDeclaredField("random");
        random.setAccessible(true);
        Assert.assertNotNull(random.get(mySSLContextSpi));

        KeyManager[] kms = new KeyManager[2];
        kms[0] = new KeyManagerImpl();
        X509KeyManager x509KeyManager = Mockito.mock(X509KeyManager.class);
        kms[1] = x509KeyManager;

        TrustManager[] tms = new TrustManager[3];
        tms[0] = new TrustManagerImpl();
        tms[1] = Mockito.mock(X509TrustManager.class);
        tms[2] = Mockito.mock(X509TrustManager.class);

        engineInitMethod.invoke(mySSLContextSpi, kms, tms, new SecureRandom());
        Field keyManager = GMSSLContextSpi.class.getDeclaredField("keyManager");
        keyManager.setAccessible(true);
        Assert.assertEquals(x509KeyManager, keyManager.get(mySSLContextSpi));
    }

    class KeyManagerImpl implements KeyManager {
    }

    class TrustManagerImpl implements TrustManager {
    }
}
