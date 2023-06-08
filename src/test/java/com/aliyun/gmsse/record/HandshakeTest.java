package com.aliyun.gmsse.record;

import org.junit.Assert;
import org.junit.Test;

import com.aliyun.gmsse.record.Handshake.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class HandshakeTest {
    @Test
    public void getValueTest() {
        Assert.assertEquals(1, Handshake.Type.getInstance(1).getValue());
        Assert.assertEquals(2, Handshake.Type.getInstance(2).getValue());
        Assert.assertEquals(11, Handshake.Type.getInstance(11).getValue());
        Assert.assertEquals(12, Handshake.Type.getInstance(12).getValue());
        Assert.assertEquals(13, Handshake.Type.getInstance(13).getValue());
        Assert.assertEquals(14, Handshake.Type.getInstance(14).getValue());
        Assert.assertEquals(15, Handshake.Type.getInstance(15).getValue());
        Assert.assertEquals(16, Handshake.Type.getInstance(16).getValue());
        Assert.assertEquals(20, Handshake.Type.getInstance(20).getValue());
        Assert.assertNull(Handshake.Type.getInstance(3));
    }

    @Test
    public void getBytesTest() throws Exception {
        Type type = new Type(1);
        Body body = new Body() {
            @Override
            public byte[] getBytes() throws IOException {
                return "test".getBytes();
            }
        };
        Handshake handshake = new Handshake(type, body);
        byte[] bytes = handshake.getBytes();
        Assert.assertArrayEquals(new byte[] {
            0x01, 0x00, 0x00, 0x04, 0x74, 0x65, 0x73, 0x74
        }, bytes);
    }

    @Test
    public void readTest() throws Exception {
        InputStream inputStream = new ByteArrayInputStream(new byte[]{0x01});
        Handshake handshake = Handshake.read(inputStream);
        Assert.assertEquals(Handshake.Type.CLIENT_HELLO, handshake.type);

        inputStream = new ByteArrayInputStream(new byte[]{0x02});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(Handshake.Type.SERVER_HELLO, handshake.type);

        inputStream = new ByteArrayInputStream(new byte[]{0x0c});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(Handshake.Type.SERVER_KEY_EXCHANGE, handshake.type);

        inputStream = new ByteArrayInputStream(new byte[]{0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(Handshake.Type.CERTIFICATE_REQUEST, handshake.type);

        inputStream = new ByteArrayInputStream(new byte[]{0x0e});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(Handshake.Type.SERVER_HELLO_DONE, handshake.type);

        inputStream = new ByteArrayInputStream(new byte[]{0x0f});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(Handshake.Type.CERTIFICATE_VERIFY, handshake.type);

        inputStream = new ByteArrayInputStream(new byte[]{0x10});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(Handshake.Type.CLIENT_KEY_EXCHANGE, handshake.type);

        inputStream = new ByteArrayInputStream(new byte[]{0x14, 0x00, 0x00, 0x00});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(Handshake.Type.FINISHED, handshake.type);

        inputStream = new ByteArrayInputStream(new byte[]{66});
        handshake = Handshake.read(inputStream);
        Assert.assertNull(handshake.type);
    }
}
