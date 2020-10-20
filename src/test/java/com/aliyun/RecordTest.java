package com.aliyun;

import com.aliyun.record.ChangeCipherSpec;
import com.aliyun.record.Handshake;
import org.junit.Assert;
import org.junit.Test;
import com.aliyun.Record.*;
import org.mockito.Mockito;

import java.io.*;

public class RecordTest {

    // @Test
    // public void writeToTest() throws Exception {
    //     byte[] bytes = new byte[]{1};
    //     Fragment fragment = Mockito.mock(Fragment.class);
    //     Mockito.when(fragment.getBytes()).thenReturn(bytes);
    //     Record record = new Record(ContentType.ALERT, ProtocolVersion.NTLS_1_1, fragment);
    //     ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    //     record.writeTo(outputStream);
    //     bytes = outputStream.toByteArray();
    //     Assert.assertEquals(21, bytes[0]);
    //     Assert.assertEquals(1, bytes[1]);
    //     Assert.assertEquals(1, bytes[2]);
    //     Assert.assertEquals(0, bytes[3]);
    //     Assert.assertEquals(1, bytes[4]);
    //     Assert.assertEquals(1, bytes[5]);
    // }

    // @Test
    // public void readTest() throws Exception {
    //     ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[]{20});
    //     Record record = Record.read(inputStream);
    //     Fragment fragment = record.fragment;
    //     Assert.assertTrue(fragment instanceof ChangeCipherSpec);

    //     try {
    //         inputStream = new ByteArrayInputStream(new byte[]{21});
    //         record = Record.read(inputStream);
    //         Assert.fail();
    //     } catch (IOException e) {
    //         Assert.assertEquals("unknow description", e.getMessage());
    //     }

    //     inputStream = new ByteArrayInputStream(new byte[]{22});
    //     record = Record.read(inputStream);
    //     fragment = record.fragment;
    //     Assert.assertTrue(fragment instanceof Handshake);

    //     inputStream.reset();
    //     record = Record.read(inputStream, true);
    //     fragment = record.fragment;
    //     Assert.assertNull(fragment);

    //     inputStream = new ByteArrayInputStream(new byte[]{23});
    //     try {
    //         Record.read(inputStream);
    //         Assert.fail();
    //     } catch (IOException e) {
    //         Assert.assertEquals("unexpected content type", e.getMessage());
    //     }

    //     try {
    //         Record.read(inputStream, true);
    //         Assert.fail();
    //     } catch (IOException e) {
    //         Assert.assertEquals("unexpected content type", e.getMessage());
    //     }

    // }

    @Test
    public void getInstanceTest() {
        ContentType contentType = Record.ContentType.getInstance(24);
        Assert.assertEquals("content type: site2site", contentType.toString());
    }
}
