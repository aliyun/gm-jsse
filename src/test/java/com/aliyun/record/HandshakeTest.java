package com.aliyun.record;

import org.junit.Assert;
import org.junit.Test;
import com.aliyun.record.Handshake.*;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static org.mockito.Mockito.when;


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
        Type type = Mockito.mock(Type.class);
        Body body = Mockito.mock(Body.class);
        when(type.getValue()).thenReturn(1);
        when(body.getBytes()).thenReturn("test".getBytes("UTF-8"));

        Handshake handshake = new Handshake(type, body);
        byte[] bytes = handshake.getBytes();
        Assert.assertTrue(new String(bytes, "UTF-8").contains("test"));
    }

    @Test
    public void readTest() throws Exception {
        InputStream inputStream = new ByteArrayInputStream(new byte[]{0x01});
        Handshake handshake = Handshake.read(inputStream);
        Assert.assertEquals(1, handshake.type.getValue());

        inputStream = new ByteArrayInputStream(new byte[]{0x02});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(2, handshake.type.getValue());

        inputStream = new ByteArrayInputStream(new byte[]{0x0c});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(12, handshake.type.getValue());

        inputStream = new ByteArrayInputStream(new byte[]{0x0d});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(13, handshake.type.getValue());

        inputStream = new ByteArrayInputStream(new byte[]{0x0e});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(14, handshake.type.getValue());

        inputStream = new ByteArrayInputStream(new byte[]{0x0f});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(15, handshake.type.getValue());

        inputStream = new ByteArrayInputStream(new byte[]{0x10});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(16, handshake.type.getValue());

        inputStream = new ByteArrayInputStream(new byte[]{0x14, 0x00, 0x00, 0x00});
        handshake = Handshake.read(inputStream);
        Assert.assertEquals(20, handshake.type.getValue());

        inputStream = new ByteArrayInputStream(new byte[]{66});
        handshake = Handshake.read(inputStream);
        Assert.assertNull(handshake.type);
    }
}
