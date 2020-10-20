package com.aliyun.gmsse.handshake;

import org.junit.Assert;
import org.junit.Test;

public class CertificateRequestTest {

    @Test
    public void nullTest() throws Exception{
        new CertificateVerify();
        Assert.assertNull(CertificateRequest.read(null));
        Assert.assertNull(new CertificateRequest().getBytes());
    }
}
