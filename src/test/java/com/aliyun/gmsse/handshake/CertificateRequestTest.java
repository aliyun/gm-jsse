package com.aliyun.gmsse.handshake;

import java.util.Vector;

import org.junit.Assert;
import org.junit.Test;

public class CertificateRequestTest {

    @Test
    public void getBytesTest() throws Exception{
        short[] types = new short[] {1, 2, 3};
        Vector<byte[]> v = new Vector<>();
        byte[] expected = new byte[] {0x03, 0x01, 0x02, 0x03, 0x00, 0x00};
        Assert.assertArrayEquals(expected, new CertificateRequest(types, v).getBytes());
    }
}
