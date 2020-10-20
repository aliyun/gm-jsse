package com.aliyun.gmsse.record;

import com.aliyun.gmsse.ProtocolVersion;
import com.aliyun.gmsse.Record;
import com.aliyun.gmsse.RecordStream;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class AppDataOutputStreamTest {

    @Test
    public void writeTest() throws Exception {
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1,
                new byte[]{1, 2, 3, 4});
        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Mockito.doNothing().when(recordStream).write(record, true);
        AppDataOutputStream appDataOutputStream = Mockito.spy(new AppDataOutputStream(recordStream));
        appDataOutputStream.write(0);
        Mockito.verify(appDataOutputStream, Mockito.times(1)).write(0);

        try {
            appDataOutputStream.write(null, 0, 1);
            Assert.fail();
        } catch (NullPointerException e) {
            Assert.assertEquals(null, e.getMessage());
        }

        byte[] bytes = new byte[]{1};
        try {
            appDataOutputStream.write(bytes, 2, 1);
            Assert.fail();
        } catch (IndexOutOfBoundsException e) {
            Assert.assertEquals(null, e.getMessage());
        }

        appDataOutputStream.write(bytes, 0, 0);
        Mockito.verify(appDataOutputStream, Mockito.times(1)).write(bytes, 0, 0);
    }

    @Test
    public void flushTest() throws Exception {
        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Mockito.doNothing().when(recordStream).flush();
        AppDataOutputStream appDataOutputStream = Mockito.spy(new AppDataOutputStream(recordStream));
        appDataOutputStream.flush();
        Mockito.verify(appDataOutputStream, Mockito.times(1)).flush();
    }
}
