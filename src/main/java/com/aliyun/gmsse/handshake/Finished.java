package com.aliyun.gmsse.handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import com.aliyun.gmsse.Util;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;

public class Finished extends Handshake.Body {

    private byte[] verifyData;

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
