package com.aliyun.gmsse.record;

import java.io.IOException;

public interface RecordFragment {
    public byte[] getBytes() throws IOException;
}
