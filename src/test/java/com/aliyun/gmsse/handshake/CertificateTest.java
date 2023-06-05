package com.aliyun.gmsse.handshake;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.mockito.Mockito.when;

public class CertificateTest {

    @Test
    public void readTest() throws Exception {
        try {
            Certificate.read(new ByteArrayInputStream("test".getBytes("UTF-8")));
            Assert.fail();
        } catch (EOFException e) {
            Assert.assertEquals("unexpected end of stream", e.getMessage());
        }
    }

    @Test
    public void toStringTest() throws Exception {
        X509Certificate test = Mockito.mock(X509Certificate.class);
        when(test.toString()).thenReturn("test");
        X509Certificate[] certs = new X509Certificate[]{test};
        Certificate certificate = new Certificate(certs);
        String str = certificate.toString();
        Assert.assertTrue(str.contains("struct {"));
        Assert.assertTrue(str.contains("certificateList ="));
        Assert.assertTrue(str.contains("test"));
        Assert.assertTrue(str.contains("} Certificate;"));
        String newLine = System.getProperty("line.separator");
        Assert.assertEquals("struct {" + newLine +
                "  certificateList =" + newLine +
                "    test" + newLine +
                "} Certificate;" + newLine, str);
    }

    @Test
    public void getTest() throws Exception {
        X509Certificate test = Mockito.mock(X509Certificate.class);
        Mockito.when(test.getEncoded()).thenReturn(new byte[]{1, 2, 3, 4});
        X509Certificate[] certs = new X509Certificate[]{test};
        Certificate certificate = new Certificate(certs);
        byte[] bytes = certificate.getBytes();
        byte[] source = new byte[]{0, 0, 7, 0, 0, 4, 1, 2, 3, 4};
        Assert.assertTrue(Arrays.equals(source, bytes));
        Assert.assertArrayEquals(certs, certificate.getCertificates());
    }

}
