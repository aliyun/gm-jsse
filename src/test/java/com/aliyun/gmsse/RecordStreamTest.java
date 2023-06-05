package com.aliyun.gmsse;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.*;
import java.lang.reflect.Field;

public class RecordStreamTest {
    private String path = this.getClass().getClassLoader().getResource("TestFile").getPath();

    @Test
    public void writeTest() throws Exception {
        FileInputStream inputStream = new FileInputStream(path);
        FileOutputStream outputStream = new FileOutputStream(path);
        RecordStream recordStream = Mockito.spy(new RecordStream(inputStream, outputStream));
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, "test".getBytes("UTF-8"));
        recordStream.write(record);
        Mockito.verify(recordStream, Mockito.times(1)).write(record);
    }

    @Test
    public void readTest() {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(new byte[]{21});
        RecordStream recordStream = new RecordStream(byteArrayInputStream, null);
        try {
            recordStream.read();
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("unexpected end of stream", e.getMessage());
        }
    }

    @Test
    public void decryptTest() throws Exception {
        FileInputStream inputStream = new FileInputStream(path);
        FileOutputStream outputStream = new FileOutputStream(path);
        RecordStream recordStream = Mockito.spy(new RecordStream(inputStream, outputStream));
        byte[] bytes = "test-test-test-test-test-test-test-test-test-test-test-test-test-test".getBytes("UTF-8");
        recordStream.setDecryptIV(new byte[16]);
        recordStream.setDecryptMacKey(new byte[]{11});
        SM4Engine sm4Engine = Mockito.mock(SM4Engine.class);
        Mockito.when(sm4Engine.processBlock(new byte[1], 0, new byte[1], 0)).thenReturn(1);
        recordStream.setReadCipher(sm4Engine);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, bytes);
        try {
            recordStream.decrypt(record);
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("bad_record_mac", e.getMessage());
        }
    }

    @Test
    public void encryptTest() throws Exception {
        FileInputStream inputStream = new FileInputStream(path);
        FileOutputStream outputStream = new FileOutputStream(path);
        RecordStream recordStream = Mockito.spy(new RecordStream(inputStream, outputStream));
        byte[] bytes = "test-test-test-test-test-test-test-test-test-test-test-test-test-test".getBytes("UTF-8");
        SM4Engine sm4Engine = Mockito.mock(SM4Engine.class);
        Mockito.when(sm4Engine.processBlock(new byte[1], 0, new byte[1], 0)).thenReturn(1);
        recordStream.setEncryptMacKey(bytes);
        recordStream.setEncryptIV(bytes);
        recordStream.setWriteCipher(sm4Engine);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, "test".getBytes("UTF-8"));
        record = recordStream.encrypt(record);

        Field contentType = Record.class.getDeclaredField("contentType");
        contentType.setAccessible(true);
        Field version = Record.class.getDeclaredField("version");
        version.setAccessible(true);
        Assert.assertEquals(contentType.get(record), Record.ContentType.ALERT);
        Assert.assertEquals(version.get(record), ProtocolVersion.NTLS_1_1);
        Assert.assertEquals(112, record.fragment.length);
    }

    @Test
    public void flushTest() throws Exception {
        FileInputStream inputStream = new FileInputStream(path);
        FileOutputStream outputStream = new FileOutputStream(path);
        RecordStream recordStream = Mockito.spy(new RecordStream(inputStream, outputStream));
        recordStream.flush();
        Mockito.verify(recordStream, Mockito.times(1)).flush();
    }
}
