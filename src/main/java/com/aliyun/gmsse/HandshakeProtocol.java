package com.aliyun.gmsse;

import java.io.IOException;

public class HandshakeProtocol {

    private RecordStream recordStream;

    public void closeInbound() throws IOException {
        this.recordStream.getInputStream().close();
    }

    public void closeOutbound() throws IOException {
        this.recordStream.getOutputStream().close();
    }
}
