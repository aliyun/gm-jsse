package com.aliyun.gmsse.record;

import org.junit.Assert;
import org.junit.Test;
import com.aliyun.gmsse.record.Alert.*;

import java.io.ByteArrayInputStream;

public class AlertTest {

    @Test
    public void getBytesTest() throws Exception{
        Level level = Level.getInstance(0);
        Description description = Description.getInstance(200);
        Alert alert = new Alert(level, description);
        byte[] bytes = alert.getBytes();
        Assert.assertEquals(0, bytes[0]);
        Assert.assertEquals(-56, bytes[1]);
    }

    @Test
    public void getDescriptionTest() throws Exception{
        Level level = new Level(0, "test");
        Description description = new Description(0, "test");
        Alert alert = new Alert(level, description);
        Assert.assertEquals(description, alert.getDescription());
    }

    @Test
    public void getDescriptionInstanceTest() throws Exception{
        Description description = Description.getInstance(0);
        Assert.assertEquals(Description.CLOSE_NOTIFY, description);

        description = Description.getInstance(10);
        Assert.assertEquals(Description.UNEXPECTED_MESSAGE, description);

        description = Description.getInstance(20);
        Assert.assertEquals(Description.BAD_RECORD_MAC, description);

        description = Description.getInstance(21);
        Assert.assertEquals(Description.DECRYPTION_FAILED, description);

        description = Description.getInstance(22);
        Assert.assertEquals(Description.RECORD_OVERFLOW, description);

        description = Description.getInstance(30);
        Assert.assertEquals(Description.DECOMPRESION_FAILURE, description);

        description = Description.getInstance(40);
        Assert.assertEquals(Description.HANDSHAKE_FAILURE, description);

        description = Description.getInstance(42);
        Assert.assertEquals(Description.BAD_CERTIFICATE, description);

        description = Description.getInstance(43);
        Assert.assertEquals(Description.UNSUPPORTED_CERTIFICATE, description);

        description = Description.getInstance(44);
        Assert.assertEquals(Description.CERTIFICATE_REVOKED, description);

        description = Description.getInstance(45);
        Assert.assertEquals(Description.CERTIFICATE_EXPIRED, description);

        description = Description.getInstance(46);
        Assert.assertEquals(Description.CERTIFICATE_UNKNOWN, description);

        description = Description.getInstance(47);
        Assert.assertEquals(Description.ILEGAL_PARAMETER, description);

        description = Description.getInstance(48);
        Assert.assertEquals(Description.UNKNOWN_CA, description);

        description = Description.getInstance(49);
        Assert.assertEquals(Description.ACES_DENIED, description);

        description = Description.getInstance(50);
        Assert.assertEquals(Description.DECODE_ERROR, description);

        description = Description.getInstance(51);
        Assert.assertEquals(Description.DECRYPT_ERROR, description);

        description = Description.getInstance(70);
        Assert.assertEquals(Description.PROTOCOL_VERSION, description);

        description = Description.getInstance(71);
        Assert.assertEquals(Description.INSUFICIENT_SECURITY, description);

        description = Description.getInstance(80);
        Assert.assertEquals(Description.INTERNAL_ERROR, description);

        description = Description.getInstance(90);
        Assert.assertEquals(Description.USER_CANCELED, description);

        description = Description.getInstance(200);
        Assert.assertEquals(Description.UNSUPPORTED_SITE2SITE, description);

        description = Description.getInstance(201);
        Assert.assertEquals(Description.NO_AREA, description);

        description = Description.getInstance(202);
        Assert.assertEquals(Description.UNSUPPORTED_AREATYPE, description);

        description = Description.getInstance(203);
        Assert.assertEquals(Description.BAD_IBCPARAM, description);

        description = Description.getInstance(204);
        Assert.assertEquals(Description.UNSUPPORTED_IBCPARAM, description);

        description = Description.getInstance(205);
        Assert.assertEquals(Description.IDENTITY_NEED, description);
        Assert.assertEquals("identity_need", description.toString());
    }

    @Test
    public void getLeveInstanceTest() throws Exception {
        Level level = Level.getInstance(1);
        Assert.assertEquals(Level.WARNING, level);

        level = Level.getInstance(2);
        Assert.assertEquals(Level.FATAL, level);
    }

    @Test
    public void readTest() throws Exception{
        Alert alert = Alert.read(new ByteArrayInputStream("test".getBytes("UTF-8")));
        Assert.assertNotNull(alert);
    }
}
