package com.aliyun.gmsse.handshake;

import java.util.Vector;

import org.junit.Assert;
import org.junit.Test;

public class CertificateRequestTest {

    @Test
    public void nullTest() throws Exception{
        short[] types = new short[] {1, 2, 3};
        Vector<byte[]> v = new Vector<>();
        Assert.assertNull(new CertificateRequest(types, v).getBytes());
    }
}
