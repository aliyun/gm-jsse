package com.aliyun.gmsse.handshake;

import com.aliyun.gmsse.Util;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;

import java.io.*;

public class ClientKeyExchange extends Handshake.Body {

    private byte[] encryptedPreMasterSecret;

    public ClientKeyExchange(byte[] encryptedPreMasterSecret) {
        this.encryptedPreMasterSecret = encryptedPreMasterSecret;
    }

    public static Body read(InputStream input) throws IOException {
        int length =  (input.read() << 8 & 0xFF) + input.read() & 0xFF;
        byte[] encryptedPreMasterSecret = new byte[length];
        input.read(encryptedPreMasterSecret, 0, length);

        return new ClientKeyExchange(encryptedPreMasterSecret);
    }

    @Override
    public byte[] getBytes() throws IOException {
        byte[] encrypted = this.encryptedPreMasterSecret;
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(encrypted.length >>> 8 & 0xFF);
        bytes.write(encrypted.length & 0xFF);
        bytes.write(encrypted);
        return bytes.toByteArray();
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  encryptedPreMasterSecret =");
        out.print(Util.hexString(encryptedPreMasterSecret));
        out.println("} ClientKeyExchange;");
        return str.toString();
    }

    public byte[] getEncryptedPreMasterSecret() {
        return encryptedPreMasterSecret;
    }

}
