package com.aliyun.gmsse.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;

public class CertificateVerify  extends Handshake.Body{

    private byte[] signature;

    public CertificateVerify(byte[] signature) {
        this.signature = signature;
    }

    public static Body read(InputStream input) throws IOException {
        int length = (input.read() & 0xFF) << 8 | input.read() & 0xFF;
        byte[] signature = new byte[length];
        input.read(signature, 0, length);
        return new CertificateVerify(signature);
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

    public byte[] getSignature() {
        return signature;
    }
}
