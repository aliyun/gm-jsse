package com.aliyun.gmsse;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import com.aliyun.gmsse.record.Alert;
import com.aliyun.gmsse.record.Alert.Description;
import com.aliyun.gmsse.record.Alert.Level;

import java.io.*;

public class RecordStreamTest {

    @Test
    public void writeTest() throws Exception {
        ByteArrayInputStream is = new ByteArrayInputStream(new byte[] {});
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        RecordStream recordStream =  new RecordStream(is, os);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, "test".getBytes("UTF-8"));
        recordStream.write(record);
        Assert.assertArrayEquals(new byte[] {
            0x15, 0x01, 0x01, 0x00, 0x04, 0x74, 0x65, 0x73, 0x74
        }, os.toByteArray());
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
    public void readAlertTest() throws IOException {
        Alert alert = new Alert(Level.WARNING, Description.HANDSHAKE_FAILURE);
        byte[] bytes = alert.getBytes();
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(0x15);
        os.write(1);
        os.write(1);
        os.write((bytes.length >>> 8) & 0xFF);
        os.write((bytes.length) & 0xFF);
        os.write(bytes);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(os.toByteArray());
        RecordStream recordStream = new RecordStream(byteArrayInputStream, null);
        try {
            recordStream.read();
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("handshake_failure", e.getMessage());
        }
    }

    @Test
    public void decryptTest() throws Exception {
        ByteArrayInputStream is = new ByteArrayInputStream(new byte[] {});
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        RecordStream recordStream =  new RecordStream(is, os);
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
        ByteArrayInputStream is = new ByteArrayInputStream(new byte[] {});
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        RecordStream recordStream =  new RecordStream(is, os);
        byte[] bytes = "test-test-test-test-test-test-test-test-test-test-test-test-test-test".getBytes("UTF-8");
        SM4Engine sm4Engine = Mockito.mock(SM4Engine.class);
        Mockito.when(sm4Engine.processBlock(new byte[1], 0, new byte[1], 0)).thenReturn(1);
        recordStream.setEncryptMacKey(bytes);
        recordStream.setEncryptIV(bytes);
        recordStream.setWriteCipher(sm4Engine);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, "test".getBytes("UTF-8"));
        record = recordStream.encrypt(record);

        Assert.assertEquals(record.contentType, Record.ContentType.ALERT);
        Assert.assertEquals(record.version, ProtocolVersion.NTLS_1_1);
        Assert.assertEquals(112, record.fragment.length);
    }

    @Test
    public void flushTest() throws Exception {
        ByteArrayInputStream is = new ByteArrayInputStream(new byte[] {});
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        RecordStream recordStream = Mockito.spy(new RecordStream(is, os));
        recordStream.flush();
        Mockito.verify(recordStream, Mockito.times(1)).flush();
    }
}
