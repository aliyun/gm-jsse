package com.aliyun.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import com.aliyun.CipherSuite;
import com.aliyun.CompressionMethod;
import com.aliyun.ProtocolVersion;
import com.aliyun.Util;
import com.aliyun.record.Handshake;

public class ServerHello extends Handshake.Body {

    private byte[] random;
    private byte[] sessionId;
    private CipherSuite suite;
    private CompressionMethod compression;
    private ProtocolVersion version;

    public ServerHello(ProtocolVersion version, byte[] random, byte[] sessionId, CipherSuite suite,
            CompressionMethod compression) {
        this.version = version;
        this.random = random;
        this.sessionId = sessionId;
        this.suite = suite;
        this.compression = compression;
    }

    public CipherSuite getCipherSuite() {
        return suite;
    }

    public static ServerHello read(InputStream input) throws IOException {
        // version
        int major = input.read() & 0xFF;
        int minor = input.read() & 0xFF;
        ProtocolVersion version = ProtocolVersion.getInstance(major, minor);

        // random
        byte[] random = new byte[32];
        input.read(random, 0, 32);

        // session id
        int sessionIdLength = input.read() & 0xFF;
        byte[] sessionId = new byte[sessionIdLength];
        input.read(sessionId, 0, sessionIdLength);

        // cipher
        int id1 = input.read();
        int id2 = input.read();
        CipherSuite suite = CipherSuite.resolve(id1, id2, version);

        // compression
        CompressionMethod compression = CompressionMethod.getInstance(input.read() & 0xFF);
        return new ServerHello(version, random, sessionId, suite, compression);
    }

    @Override
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // version
        out.write(version.getMajor());
        out.write(version.getMinor());
        // random
        out.write(random);
        // session id
        out.write(sessionId.length);
        out.write(sessionId);
        // cipher
        out.write(suite.getId());
        // compression
        out.write(compression.getValue());
        return out.toByteArray();
    }

    public byte[] getRandom() {
        return random;
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  version = " + version + ";");
        out.println("  random = " + Util.hexString(random) + ";");
        out.println("  sessionId = " + Util.hexString(sessionId) + ";");
        out.println("  cipherSuite = " + suite.getName() + ";");
        out.println("  compressionMethod = " + compression.toString() + ";");
        out.println("} ServerHello;");
        return str.toString();
    }

    public CompressionMethod getCompressionMethod() {
        return compression;
    }

    public byte[] getSessionId() {
        return sessionId.clone();
    }
}