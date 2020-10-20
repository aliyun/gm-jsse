package com.aliyun.gmsse.handshake;

import java.io.IOException;
import java.io.InputStream;

import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;


public class CertificateRequest extends Handshake.Body {

    @Override
    public byte[] getBytes() throws IOException {
        return null;
    }

    public static Body read(InputStream input) {
        return null;
    }

}
