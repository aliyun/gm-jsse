package com.aliyun.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.aliyun.Util;
import com.aliyun.record.Handshake;

import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ServerKeyExchange extends Handshake.Body {

    public byte[] signature;

    public ServerKeyExchange(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int length = signature.length;
        os.write(length >>> 8 & 0xFF);
        os.write(length & 0xFF);
        os.write(signature);
        return os.toByteArray();
    }

    public static ServerKeyExchange read(InputStream input) throws IOException {
        int signatureLength = (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
        byte[] signature = new byte[signatureLength];
        input.read(signature, 0, signature.length);
        return new ServerKeyExchange(signature);
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  signedParams = " + Util.hexString(signature) + ";");
        out.println("} ServerKeyExchange;");
        return str.toString();
    }

    public boolean verify(PublicKey publicKey, byte[] clientRandom, byte[] serverRandom, X509Certificate encryptionCert)
            throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            SignatureException, CertificateEncodingException {
        byte[] certBytes = encryptionCert.getEncoded();
        int length = certBytes.length;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write((length >>> 16) & 0xff);
        baos.write((length >>> 8) & 0xff);
        baos.write(length & 0xff);
        baos.write(certBytes);

        Signature s = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
        SM2ParameterSpec spec = new SM2ParameterSpec("1234567812345678".getBytes());
        s.setParameter(spec);
        s.initVerify(publicKey);
        s.update(clientRandom);
        s.update(serverRandom);
        s.update(baos.toByteArray());
        return s.verify(signature);
    }
}
