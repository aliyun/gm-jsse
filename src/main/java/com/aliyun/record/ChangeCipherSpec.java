package com.aliyun.record;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

public class ChangeCipherSpec implements RecordFragment {

    @Override
    public byte[] getBytes() throws IOException {
        return new byte[] { 0x01 };
    }

    public static ChangeCipherSpec read(InputStream input) throws IOException {
        // read the 0x01
        input.read();
        return new ChangeCipherSpec();
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  type = change_cipher_spec ;");
        out.println("} ChangeCipherSpec;");
        return str.toString();
    }
}
