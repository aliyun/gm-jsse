package com.aliyun.gmsse.record;

import java.io.IOException;
import java.io.OutputStream;

import com.aliyun.gmsse.ProtocolVersion;
import com.aliyun.gmsse.Record;
import com.aliyun.gmsse.RecordStream;
import com.aliyun.gmsse.Record.ContentType;

public class AppDataOutputStream extends OutputStream {

    private RecordStream recordStream;

    public AppDataOutputStream(RecordStream recordStream) {
        this.recordStream = recordStream;
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] { (byte) b }, 0, 1);
    }

    @Override
    public void write(byte b[], int off, int len) throws IOException {
        if (b == null) {
            throw new NullPointerException();
        } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length) || ((off + len) < 0)) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return;
        }

        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        byte[] content = new byte[len];
        System.arraycopy(b, off, content, 0, len);
        Record recored = new Record(ContentType.APPLICATION_DATA, version, content);
        recordStream.write(recored, true);
    }

    @Override
    public void flush() throws IOException {
        recordStream.flush();
    }

}
