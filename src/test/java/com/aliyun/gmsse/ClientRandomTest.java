package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;

public class ClientRandomTest {

    @Test
    public void toStringTest() throws Exception{
        ClientRandom clientRandom = new ClientRandom(1, new byte[]{1});
        String str = clientRandom.toString();
        Assert.assertTrue(str.contains("gmt_unix_time = 1;"));
        Assert.assertTrue(str.contains("random_bytes = 01"));
    }

    @Test
    public void getBytesTest() throws Exception{
        ClientRandom clientRandom = new ClientRandom(1, new byte[]{1});
        byte[] bytes = clientRandom.getBytes();
        Assert.assertEquals(0, bytes[0]);
        Assert.assertEquals(0, bytes[1]);
        Assert.assertEquals(0, bytes[2]);
        Assert.assertEquals(1, bytes[3]);
        Assert.assertEquals(1, bytes[4]);
    }
}
