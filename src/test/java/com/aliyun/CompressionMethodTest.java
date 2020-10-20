package com.aliyun;

import com.aliyun.gmsse.CompressionMethod;
import org.junit.Assert;
import org.junit.Test;

public class CompressionMethodTest {

    @Test
    public void getInstanceTest() {
        Assert.assertEquals(CompressionMethod.NULL, CompressionMethod.getInstance(0));
        Assert.assertEquals(CompressionMethod.ZLIB, CompressionMethod.getInstance(1));
    }
}
