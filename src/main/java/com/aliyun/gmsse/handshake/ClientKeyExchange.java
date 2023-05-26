package com.aliyun.gmsse.handshake;

import com.aliyun.gmsse.ProtocolVersion;
import com.aliyun.gmsse.Util;
import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.io.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class ClientKeyExchange extends Handshake.Body {

    private byte[] preMasterSecret;
    private byte[] encryptedPreMasterSecret;

    public ClientKeyExchange(ProtocolVersion version, SecureRandom random, X509Certificate certificate)
            throws IOException {
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        ba.write(version.getMajor());
        ba.write(version.getMinor());
        ba.write(random.generateSeed(46));
        this.preMasterSecret = ba.toByteArray();
        try {
            this.encryptedPreMasterSecret = Crypto.encrypt((BCECPublicKey) certificate.getPublicKey(), this.preMasterSecret);
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public static Body read(InputStream input) {
        return null;
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

    public byte[] getPreMasterSecret() {
        return preMasterSecret;
    }

    public byte[] getMasterSecret(byte[] clientRandom, byte[] serverRandom) throws IOException {
        byte[] MASTER_SECRET = "master secret".getBytes();
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(clientRandom);
        os.write(serverRandom);
        byte[] seed = os.toByteArray();
        try {
            return Crypto.prf(preMasterSecret, MASTER_SECRET, seed, preMasterSecret.length);
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }
}
