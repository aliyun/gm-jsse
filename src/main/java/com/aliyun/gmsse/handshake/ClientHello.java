package com.aliyun.gmsse.handshake;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.aliyun.gmsse.ProtocolVersion;
import com.aliyun.gmsse.CipherSuite;
import com.aliyun.gmsse.CompressionMethod;
import com.aliyun.gmsse.ClientRandom;
import com.aliyun.gmsse.Util;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;

public class ClientHello extends Handshake.Body {
    ClientRandom random;
    byte[] sessionId;
    private List<CipherSuite> suites;
    private List<CompressionMethod> compressions;
    private ProtocolVersion version;

    public ClientHello(ProtocolVersion version, ClientRandom random, byte[] sessionId, List<CipherSuite> suites,
            List<CompressionMethod> compressions) {
        this.version = version;
        this.random = random;
        this.sessionId = sessionId;
        this.suites = suites;
        this.compressions = compressions;
    }

    public ProtocolVersion getProtocolVersion() {
        return version;
    }

    public ClientRandom getClientRandom() {
        return random;
    }

    public List<CipherSuite> getCipherSuites() {
        return suites;
    }

    public List<CompressionMethod> getCompressionMethods() {
        return compressions;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  version = " + version + ";");
        BufferedReader r = new BufferedReader(new StringReader(random.toString()));
        String s;
        try {
            while ((s = r.readLine()) != null) {
                out.print("  ");
                out.println(s);
            }
        } catch (IOException ignored) {
        }
        out.println("  sessionId = " + Util.hexString(sessionId) + ";");
        out.println("  cipherSuites = {");
        for (Iterator<CipherSuite> i = suites.iterator(); i.hasNext();) {
            out.print("    ");
            out.println(i.next().getName());
        }
        out.println("  };");
        out.print("  compressionMethods = { ");
        for (Iterator<CompressionMethod> i = compressions.iterator(); i.hasNext();) {
            out.print(i.next().toString());
            if (i.hasNext()) {
                out.print(", ");
            }
        }
        out.println(" };");
        out.println("} ClientHello;");
        return str.toString();
    }

    @Override
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        // write version
        ba.write(version.getMajor());
        ba.write(version.getMinor());
        // write random
        ba.write(random.getBytes());
        // write cipher suites
        int length = suites.size() * 4;
        ba.write(length >>> 16 & 0xFF);
        ba.write(length >>> 8 & 0xFF);
        ba.write(length & 0xFF);
        for (CipherSuite suite : suites) {
            ba.write(suite.getId());
            ba.write(suite.getKeyLength() >>> 8 & 0xFF);
            ba.write(suite.getKeyLength() & 0xFF);
        }

        // write compress
        ba.write(compressions.size());
        for (CompressionMethod c : compressions) {
            ba.write(c.getValue());
        }

        return ba.toByteArray();
    }

    public static Body read(InputStream input) throws IOException {
        // version
        int major = input.read() & 0xFF;
        int minor = input.read() & 0xFF;
        ProtocolVersion version = ProtocolVersion.getInstance(major, minor);

        int gmtUnixTime = (input.read() & 0xFF) << 24 | (input.read() & 0xFF) << 16| (input.read() & 0xFF) << 8 | input.read() & 0xFF;
        byte[] randomBytes = new byte[28];
        input.read(randomBytes, 0, 28);
        ClientRandom random = new ClientRandom(gmtUnixTime, randomBytes);

        // session id 由服务端决定，因此不存在

        int suiteSize =  (input.read() << 16 & 0xFF) + (input.read() << 8 & 0xFF) + input.read() & 0xFF;
        List<CipherSuite> suites = new ArrayList<CipherSuite>();
        for (int i = 0; i < suiteSize / 4; i++) {
            int id1 = input.read();
            int id2 = input.read();
            int size = (input.read() & 0xFF) << 8 | input.read();
            suites.add(new CipherSuite(null, null, null, null, size, id1, id2, null, ProtocolVersion.NTLS_1_1));
        }

        int compressionLength = input.read();
        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>();
        for (int i = 0; i < compressionLength; i++) {
            compressions.add(CompressionMethod.getInstance(input.read() & 0xFF));
        }

        return new ClientHello(version, random, null, suites, compressions);
    }
}
