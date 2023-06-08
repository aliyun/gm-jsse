package com.aliyun.gmsse.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
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
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        // write type length
        int length = this.certificateTypes.length;
        ba.write(length);
        // write types
        for (int i = 0; i < length; i++) {
            ba.write(this.certificateTypes[i]);
        }

        // write ca length
        Iterator<byte[]> it = this.certificateAuthorities.iterator();
        int casLength = 0;
        while (it.hasNext()) {
            byte[] ca = it.next();
            casLength += ca.length + 2;
        }

        ba.write(casLength >>> 8 & 0xFF);
        ba.write(casLength & 0xFF);

        Iterator<byte[]> it2 = this.certificateAuthorities.iterator();
        while (it2.hasNext()) {
            byte[] ca = it2.next();
            ba.write(ca.length >>> 8 & 0xFF);
            ba.write(ca.length & 0xFF);
            ba.write(ca);
        }

        return ba.toByteArray();
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
            certificateAuthorities.add(encoding);
            count += nameLength + 2;
        }

        return new CertificateRequest(types, certificateAuthorities);
    }

}
