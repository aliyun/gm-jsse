package com.aliyun.gmsse.handshake;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.aliyun.gmsse.record.Handshake;

import org.bouncycastle.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

public class FinishedTest {

    @Test
    public void toStringTest() throws IOException {
        byte[] masterSecret = new byte[48];
        Arrays.fill(masterSecret, (byte)10);
        List<Handshake> recivedHandshakes = new ArrayList<>();
        Finished finished = new Finished(masterSecret, "client finished", recivedHandshakes);
        Assert.assertTrue(finished.toString().contains("verify_data = 70 cd ea 88 38 c9 95 3d  ef a9 24 be"));
    }
}
