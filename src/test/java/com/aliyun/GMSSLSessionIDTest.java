package com.aliyun;

import org.junit.Assert;
import org.junit.Test;

public class GMSSLSessionIDTest {

    @Test
    public void getTest() {
        byte[] bytes = new byte[]{1};
        GMSSLSession.ID id = new GMSSLSession.ID(bytes);
        Assert.assertArrayEquals(bytes, id.getId());
    }
}
