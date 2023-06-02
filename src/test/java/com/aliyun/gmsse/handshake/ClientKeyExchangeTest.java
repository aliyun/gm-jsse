package com.aliyun.gmsse.handshake;

import com.aliyun.gmsse.ProtocolVersion;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

public class ClientKeyExchangeTest {

    @Test
    public void toStringTest() throws Exception {
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange("encryptedPreMasterSecret".getBytes());
        String str = clientKeyExchange.toString();
        Assert.assertTrue(str.contains("struct {"));
        Assert.assertTrue(str.contains("encryptedPreMasterSecret ="));
        Assert.assertTrue(str.contains("} ClientKeyExchange;"));
    }

    @Test
    public void getBytesTest() throws Exception {
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange("encryptedPreMasterSecret".getBytes());
        byte[] bytes = clientKeyExchange.getBytes();
        Assert.assertEquals(26, bytes.length);
        ByteArrayInputStream is = new ByteArrayInputStream(bytes);
        ClientKeyExchange cke = (ClientKeyExchange)ClientKeyExchange.read(is);
        Assert.assertNotNull(cke);
        Assert.assertArrayEquals("encryptedPreMasterSecret".getBytes(), cke.getEncryptedPreMasterSecret());
    }
}
