package com.aliyun;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class ProtocolVersionTest {

    @Test
    public void compareToTest() throws Exception {
        Assert.assertEquals(1, ProtocolVersion.NTLS_1_1.compareTo(null));
        Assert.assertEquals(1, ProtocolVersion.NTLS_1_1.compareTo("null"));

        ProtocolVersion protocolVersion = ProtocolVersion.getInstance(2, 2);
        Assert.assertEquals(1, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));

        protocolVersion = ProtocolVersion.getInstance(0, 2);
        Assert.assertEquals(-1, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));

        protocolVersion = ProtocolVersion.getInstance(1, 2);
        Assert.assertEquals(1, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));

        protocolVersion = ProtocolVersion.getInstance(1, -1);
        Assert.assertEquals(-1, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));

        protocolVersion = ProtocolVersion.getInstance(1, 1);
        Assert.assertEquals(0, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));
    }

    @Test
    public void readTest() throws Exception {
        InputStream inputStream = new ByteArrayInputStream(new byte[]{1, 1});
        ProtocolVersion protocolVersion = ProtocolVersion.read(inputStream);
        byte[] bytes = protocolVersion.getEncoded();
        Assert.assertEquals(1, bytes[0]);
        Assert.assertEquals(1, bytes[1]);
    }

    @Test
    public void hachTest() {
        Assert.assertEquals(257, ProtocolVersion.NTLS_1_1.hashCode());
    }

    @Test
    public void equalsTest() {
        Assert.assertFalse(ProtocolVersion.NTLS_1_1.equals(null));
        Assert.assertFalse(ProtocolVersion.NTLS_1_1.equals("null"));
        Assert.assertTrue(ProtocolVersion.NTLS_1_1.equals(ProtocolVersion.NTLS_1_1));
    }
}
