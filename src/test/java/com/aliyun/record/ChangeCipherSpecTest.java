package com.aliyun.record;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class ChangeCipherSpecTest {
    @Test
    public void getBytesTest() throws IOException {
        ChangeCipherSpec spec = new ChangeCipherSpec();
        byte[] bytes = spec.getBytes();
        Assert.assertEquals(0x01, bytes[0]);
    }

    @Test
    public void readTest() throws IOException {
        Assert.assertNotNull(ChangeCipherSpec.read(new ByteArrayInputStream(new byte[] {0x01})));
    }

    @Test
    public void toStringTest() {
        ChangeCipherSpec spec = new ChangeCipherSpec();
        String str = spec.toString();
        Assert.assertTrue(str.contains("struct {"));
        Assert.assertTrue(str.contains("  type = change_cipher_spec ;"));
        Assert.assertTrue(str.contains("} ChangeCipherSpec;"));
    }
}
