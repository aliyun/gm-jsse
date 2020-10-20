package com.aliyun.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import com.aliyun.ProtocolVersion;
import com.aliyun.Util;
import com.aliyun.crypto.Crypto;
import com.aliyun.record.Handshake;
import com.aliyun.record.Handshake.Body;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

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
            this.encryptedPreMasterSecret = Crypto.encrypt((BCECPublicKey) certificate.getPublicKey(),
                    this.preMasterSecret);
        } catch (Exception ex) {
            RuntimeException re = new RuntimeException(ex.getMessage());
            re.initCause(ex);
            throw re;
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

    // // P_SM3(secret，label+ sed)
    // byte[] result = new byte[length];
    // hmacHash(digest, data, 0, data.length, labelSeed, result);
    // return result;

    public byte[] getMasterSecret(byte[] clientRandom, byte[] serverRandom) throws IOException {
        byte[] MASTER_SECRET = "master secret".getBytes();
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(clientRandom);
        os.write(serverRandom);
        byte[] seed = os.toByteArray();
        try {
            return Crypto.prf(preMasterSecret, MASTER_SECRET, seed, preMasterSecret.length);
        } catch (Exception ex) {
            RuntimeException re = new RuntimeException(ex.getMessage());
            re.initCause(ex);
            throw re;
        }
    }
}
