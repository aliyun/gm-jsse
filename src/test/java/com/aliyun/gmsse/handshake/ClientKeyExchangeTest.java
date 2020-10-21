package com.aliyun.gmsse.handshake;

import com.aliyun.gmsse.ProtocolVersion;
import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;

public class ClientKeyExchangeTest {

    @Test
    public void getMasterSecretTest() throws Exception {
        SecureRandom random = new SecureRandom();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(ProtocolVersion.NTLS_1_1,
                random, ServerKeyExchangeTest.cert);
        byte[] para = new byte[]{32};
        byte[] bytes = clientKeyExchange.getMasterSecret(para, para);
        Assert.assertEquals(48, bytes.length);
    }

    @Test
    public void getPreMasterSecretTest() throws Exception {
        SecureRandom random = new SecureRandom();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(ProtocolVersion.NTLS_1_1,
                random, ServerKeyExchangeTest.cert);

        byte[] bytes = clientKeyExchange.getPreMasterSecret();
        Assert.assertEquals(48, bytes.length);
    }

    @Test
    public void toStringTest() throws Exception {
        SecureRandom random = new SecureRandom();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(ProtocolVersion.NTLS_1_1,
                random, ServerKeyExchangeTest.cert);
        String str = clientKeyExchange.toString();
        Assert.assertTrue(str.contains("struct {"));
        Assert.assertTrue(str.contains("encryptedPreMasterSecret ="));
        Assert.assertTrue(str.contains("} ClientKeyExchange;"));
    }

    @Test
    public void getBytesTest() throws Exception {
        SecureRandom random = new SecureRandom();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(ProtocolVersion.NTLS_1_1,
                random, ServerKeyExchangeTest.cert);
        byte[] bytes = clientKeyExchange.getBytes();
        Assert.assertEquals(157, bytes.length);
        Assert.assertNull(ClientKeyExchange.read(null));
    }
}
