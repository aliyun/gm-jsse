package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;

public class UtilTest {
    @Test
    public void hexStringTest() {
        new Util();
        byte[] bytes = new byte[]{9, 10, 11, 12, 13, 14, 15, 16, 17};
        String string = Util.hexString(bytes);
        Assert.assertEquals("09 0a 0b 0c 0d 0e 0f 10  11\n", string);
    }
}
