package com.aliyun.gmsse.record;

import java.io.IOException;
import java.io.InputStream;

import com.aliyun.gmsse.Record;
import com.aliyun.gmsse.RecordStream;

public class AppDataInputStream extends InputStream {

    private RecordStream recordStream;
    private byte[] cacheBuffer = null;
    private int cachePos = 0;

    public AppDataInputStream(RecordStream recordStream) {
        this.recordStream = recordStream;
    }

    @Override
    public int read() throws IOException {
        byte[] buf = new byte[1];
        int ret = read(buf, 0, 1);
        return ret < 0 ? -1 : buf[0] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int length;
        if (cacheBuffer != null) {
            length = Math.min(cacheBuffer.length - cachePos, len);
            System.arraycopy(cacheBuffer, cachePos, b, off, length);

            cachePos += length;
            if (cachePos >= cacheBuffer.length) {
                cacheBuffer = null;
                cachePos = 0;
            }
        } else {
            Record record = recordStream.read(true);
            length = Math.min(record.fragment.length, len);
            System.arraycopy(record.fragment, 0, b, off, length);
            if (length < record.fragment.length) {
                cacheBuffer = record.fragment;
                cachePos = len;
            }
        }
        return length;
    }
}
