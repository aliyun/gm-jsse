package com.aliyun.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;

import javax.net.ssl.SSLException;

import com.aliyun.Util;
import com.aliyun.crypto.Crypto;
import com.aliyun.record.Handshake;
import com.aliyun.record.Handshake.Body;

public class Finished extends Handshake.Body {

    private byte[] verifyData;

    public Finished(byte[] masterSecret, String label, List<Handshake> handshakes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Handshake handshake : handshakes) {
            out.write(handshake.getBytes());
        }
        // SM3(handshake_mesages)
        byte[] seed = Crypto.hash(out.toByteArray());
        try {
            // PRF(master_secret，finished_label，SM3(handshake_mesages))[0.11]
            this.verifyData = Crypto.prf(masterSecret, label.getBytes(), seed, 12);
        } catch (Exception e) {
            throw new SSLException("caculate verify data failed", e);
        }
    }

    public Finished(byte[] verifyData) {
        this.verifyData = verifyData;
    }

    @Override
    public byte[] getBytes() throws IOException {
        return verifyData;
    }

    public static Body read(InputStream input, int msgLength) throws IOException {
        return new Finished(Util.safeRead(input, msgLength));
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  verify_data = " + Util.hexString(verifyData).trim());
        out.println("} Finished;");
        return str.toString();
    }
}
