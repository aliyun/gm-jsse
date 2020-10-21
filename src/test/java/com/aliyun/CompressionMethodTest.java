package com.aliyun;

import com.aliyun.gmsse.CompressionMethod;
import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.Field;

public class CompressionMethodTest {

    @Test
    public void getInstanceTest() throws Exception {
        CompressionMethod compressionMethod = CompressionMethod.getInstance(0);
        Field value = CompressionMethod.class.getDeclaredField("value");
        value.setAccessible(true);
        Assert.assertEquals(0, value.get(compressionMethod));
        compressionMethod = CompressionMethod.getInstance(1);
        Assert.assertEquals(1, value.get(compressionMethod));
    }
}
