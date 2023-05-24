package com.aliyun.gmsse.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;

public class CertificateVerify  extends Handshake.Body{

    private byte[] signature;

    public CertificateVerify(List<Handshake> handshakes) {

    }

    public static Body read(InputStream input) {
        return null;
    }

    @Override
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int length = signature.length;
        os.write(length >>> 8 & 0xFF);
        os.write(length & 0xFF);
        os.write(signature);
        return os.toByteArray();
    }

}
