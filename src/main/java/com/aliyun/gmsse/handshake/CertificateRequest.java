package com.aliyun.gmsse.handshake;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import com.aliyun.gmsse.record.Handshake;


public class CertificateRequest extends Handshake.Body {

    private short[] certificateTypes;
    private Vector<byte[]> certificateAuthorities;

    public CertificateRequest(short[] types, Vector<byte[]> certificateAuthorities) {
        this.certificateTypes = types;
        this.certificateAuthorities = certificateAuthorities;
    }

    @Override
    public byte[] getBytes() throws IOException {
        return null;
    }

    public static CertificateRequest read(InputStream input) throws IOException {
        int length = input.read();
        short[] types = new short[length];
        for (int i = 0; i < length; i++) {
            types[i] = (short)input.read();
        }

        int casLength = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
        int count = 0;
        Vector<byte[]> certificateAuthorities = new Vector<>();
        while (count < casLength) {
            int nameLength = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
            byte[] encoding = new byte[nameLength];
            input.read(encoding, 0, nameLength);
            // TODO:
            certificateAuthorities.add(encoding);
            count += nameLength + 2;
        }

        return new CertificateRequest(types, certificateAuthorities);
    }

}
