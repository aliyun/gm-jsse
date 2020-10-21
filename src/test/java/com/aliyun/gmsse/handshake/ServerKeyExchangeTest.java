package com.aliyun.gmsse.handshake;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertFalse;

public class ServerKeyExchangeTest {
    public static X509Certificate cert;

    static {
        try {
            String certString = "-----BEGIN CERTIFICATE-----\n" +
                    "MIIB9TCCAZugAwIBAgIGAXVFDeUmMAoGCCqBHM9VAYN1MFIxFzAVBgNVBAMMDk15\n" +
                    "IEFwcGxpY2F0aW9uMRgwFgYDVQQKDA9NeSBPcmdhbmlzYXRpb24xEDAOBgNVBAcM\n" +
                    "B015IENpdHkxCzAJBgNVBAYTAkRFMB4XDTIwMTAyMDA4MDg1OVoXDTIxMTAyMDA4\n" +
                    "MDg1OVowUjEXMBUGA1UEAwwOTXkgQXBwbGljYXRpb24xGDAWBgNVBAoMD015IE9y\n" +
                    "Z2FuaXNhdGlvbjEQMA4GA1UEBwwHTXkgQ2l0eTELMAkGA1UEBhMCREUwWTATBgcq\n" +
                    "hkjOPQIBBggqgRzPVQGCLQNCAAQgKoV6GiEL3XJ4JJv7DmzBfIX2D21mPlXLRekK\n" +
                    "9diMv6QRQhz86B1GZwSdnb7icVQawBQBDd/RfvlAoI00nwcoo10wWzAdBgNVHQ4E\n" +
                    "FgQUMpXUaNkQZwEjwZ83rsZnkexafVcwHwYDVR0jBBgwFoAUMpXUaNkQZwEjwZ83\n" +
                    "rsZnkexafVcwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAZYwCgYIKoEcz1UBg3UD\n" +
                    "SAAwRQIgckeUrFQ9DYcmqtE/hI7+Lv8tGDIYAWwWoSE/Y34BFwYCIQChVpRVxUO5\n" +
                    "QH7VqIsm8WS5I6IKDjyfbzeG74UPH3IFGA==\n" +
                    "-----END CERTIFICATE-----";
            ByteArrayInputStream certStream = new ByteArrayInputStream(certString.getBytes("UTF-8"));
            CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            cert = (X509Certificate) cf.generateCertificate(certStream);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void getBytesTest() throws Exception {
        byte[] bytes = new byte[]{66};
        ServerKeyExchange exchange = new ServerKeyExchange(bytes);
        bytes = exchange.getBytes();
        Assert.assertEquals(0, bytes[0]);
        Assert.assertEquals(1, bytes[1]);
        Assert.assertEquals(66, bytes[2]);
    }

    @Test
    public void toStringTest() throws Exception {
        byte[] bytes = new byte[]{10};
        ServerKeyExchange exchange = new ServerKeyExchange(bytes);
        Assert.assertTrue(exchange.toString().contains("signedParams = 0a"));
    }

    @Test
    public void verifyTest() throws Exception {
        byte[] bytes = new byte[]{10};
        ServerKeyExchange exchange = Mockito.spy(new ServerKeyExchange(bytes));
        PublicKey key = cert.getPublicKey();
        boolean verified = exchange.verify(key, bytes, bytes, cert);
        assertFalse(verified);
    }
}
