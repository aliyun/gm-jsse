package com.aliyun.handshake;

import java.io.IOException;
import java.io.InputStream;

import com.aliyun.record.Handshake;
import com.aliyun.record.Handshake.Body;


public class CertificateRequest extends Handshake.Body {

    @Override
    public byte[] getBytes() throws IOException {
        return null;
    }

    public static Body read(InputStream input) {
        return null;
    }

}
