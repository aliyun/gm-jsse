package com.aliyun.gmsse.handshake;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import javax.net.ssl.SSLProtocolException;

import com.aliyun.gmsse.record.Handshake;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Certificate extends Handshake.Body {

    X509Certificate[] certs;

    public Certificate(X509Certificate[] certs) {
        this.certs = certs;
    }

    @Override
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int total = 0;
        for (X509Certificate cert : certs) {
            byte[] certContent = null;
            try {
                certContent = cert.getEncoded();
            } catch (CertificateEncodingException e) {
                // ignore
            }
            int length = certContent.length;
            out.write(length >>> 16 & 0xFF);
            out.write(length >>> 8 & 0xFF);
            out.write(length & 0xFF);
            out.write(certContent);
            total += 3 + length;
        }

        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        packet.write(total >>> 16 & 0xFF);
        packet.write(total >>> 8 & 0xFF);
        packet.write(total & 0xFF);
        out.writeTo(packet);

        return packet.toByteArray();
    }

    public static Certificate read(InputStream input) throws IOException {
        // certificate length
        int len = (input.read() & 0xFF) << 16 | (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
        byte[] buf = new byte[len];
        int count = 0;
        while (count < len) {
            int l = input.read(buf, count, len - count);
            if (l == -1) {
                throw new EOFException("unexpected end of stream");
            }
            count += l;
        }
        try {
            LinkedList<X509Certificate> certs = new LinkedList<X509Certificate>();
            BouncyCastleProvider bc = new BouncyCastleProvider();
            CertificateFactory fact = CertificateFactory.getInstance("X.509", bc);
            ByteArrayInputStream bin = new ByteArrayInputStream(buf);
            count = 0;
            while (count < len) {
                int len2 = (bin.read() & 0xFF) << 16 | (bin.read() & 0xFF) << 8 | (bin.read() & 0xFF);
                certs.add((X509Certificate) fact.generateCertificate(bin));
                count += len2 + 3;
            }
            return new Certificate((X509Certificate[]) certs.toArray(new X509Certificate[certs.size()]));
        } catch (CertificateException ce) {
            SSLProtocolException sslpe = new SSLProtocolException(ce.getMessage());
            sslpe.initCause(ce);
            throw sslpe;
        }
    }

    public X509Certificate[] getCertificates() {
        return certs;
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  certificateList =");
        for (int i = 0; i < certs.length; i++) {
            BufferedReader r = new BufferedReader(new StringReader(certs[i].toString()));
            String s;
            try {
                while ((s = r.readLine()) != null) {
                    out.print("    ");
                    out.println(s);
                }
            } catch (IOException ignored) {
            }
        }
        out.println("} Certificate;");
        return str.toString();
    }
}
