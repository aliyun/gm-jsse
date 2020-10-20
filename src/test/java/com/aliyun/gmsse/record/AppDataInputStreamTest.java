package com.aliyun.gmsse.record;

import com.aliyun.gmsse.ProtocolVersion;
import com.aliyun.gmsse.Record;
import com.aliyun.gmsse.RecordStream;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class AppDataInputStreamTest {

    @Test
    public void readTest() throws Exception {
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1,
                new byte[]{1, 2, 3, 4});
        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Mockito.when(recordStream.read(true)).thenReturn(record);
        AppDataInputStream appDataInputStream = new AppDataInputStream(recordStream);
        int result = appDataInputStream.read();
        Assert.assertEquals(1, result);
        appDataInputStream.close();
    }
}
