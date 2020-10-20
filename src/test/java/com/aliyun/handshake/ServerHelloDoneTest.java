package com.aliyun.handshake;

import org.junit.Assert;
import org.junit.Test;

public class ServerHelloDoneTest {

    @Test
    public void toStringTest() {
        ServerHelloDone serverHelloDone = new ServerHelloDone();
        Assert.assertTrue(serverHelloDone.toString().contains("struct {"));
        Assert.assertTrue(serverHelloDone.toString().contains("} ServerHelloDone;"));
    }

    @Test
    public void getBytesTest() throws Exception{
        ServerHelloDone serverHelloDone = new ServerHelloDone();
        byte[] bytes = serverHelloDone.getBytes();
        Assert.assertEquals(0, bytes.length);
    }
}
