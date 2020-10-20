package com.aliyun.handshake;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;

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
}
