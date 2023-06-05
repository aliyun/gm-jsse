package com.aliyun.gmsse.handshake;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class FinishedTest {

    @Test
    public void toStringTest() throws IOException {
        Finished finished = new Finished(new byte[] {
            (byte)0x70, (byte)0xcd, (byte)0xea, (byte)0x88, 
            (byte)0x38, (byte)0xc9, (byte)0x95, (byte)0x3d,
            (byte)0xef, (byte)0xa9, (byte)0x24, (byte)0xbe
        });
        Assert.assertTrue(finished.toString().contains("verify_data = 70 cd ea 88 38 c9 95 3d  ef a9 24 be"));
    }
}
