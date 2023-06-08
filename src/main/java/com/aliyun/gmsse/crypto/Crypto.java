package com.aliyun.gmsse.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.ShortBufferException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

public class Crypto {
    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(),
            x9ECParameters.getG(), x9ECParameters.getN());

    public static byte[] encrypt(BCECPublicKey key, byte[] preMasterSecret)
            throws IOException, InvalidCipherTextException {
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(key.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        byte[] c1c3c2 = sm2Engine.processBlock(preMasterSecret, 0, preMasterSecret.length);

        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1; // sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c3Len = 32;
        byte[] c1x = new byte[32];
        // 第一个字节为固定的 0x04
        System.arraycopy(c1c3c2, 1, c1x, 0, 32); // c1x
        byte[] c1y = new byte[32];
        System.arraycopy(c1c3c2, c1x.length + 1, c1y, 0, 32); // c1y

        // 32 字节的签名
        byte[] c3 = new byte[c3Len];
        System.arraycopy(c1c3c2, c1Len, c3, 0, c3Len); // c3

        // 被加密的字节，长度与加密前的字节一致
        int c2len = c1c3c2.length - c1Len - c3Len;
        byte[] c2 = new byte[c2len];
        System.arraycopy(c1c3c2, c1Len + c3Len, c2, 0, c2len); // c2

        // 重新编码为 ASN1 格式
        return encode(c1x, c1y, c3, c2);
    }

    public static byte[] encode(byte[] c1x, byte[] c1y, byte[] c3, byte[] c2) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(new BigInteger(c1x)));
        v.add(new ASN1Integer(new BigInteger(c1y)));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        DERSequence seq = new DERSequence(v);
        return seq.getEncoded();
    }

    public static byte[] decrypt(BCECPrivateKey key, byte[] encryptedPreMasterSecret) throws IOException, InvalidCipherTextException {
        DLSequence seq = (DLSequence)ASN1Primitive.fromByteArray(encryptedPreMasterSecret);
        ASN1Integer c1xAsn1Integer = (ASN1Integer)seq.getObjectAt(0);
        byte[] c1x = c1xAsn1Integer.getValue().toByteArray();
        ASN1Integer c1yAsn1Integer = (ASN1Integer)seq.getObjectAt(1);
        byte[] c1y = c1yAsn1Integer.getValue().toByteArray();
        DEROctetString c3DEROctetString = (DEROctetString)seq.getObjectAt(2);
        byte[] c3 = c3DEROctetString.getOctets();
        DEROctetString c2DEROctetString = (DEROctetString)seq.getObjectAt(3);
        byte[] c2 = c2DEROctetString.getOctets();

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(0x04);
        os.write(c1x);
        os.write(c1y);
        os.write(c3);
        os.write(c2);
        byte[] pms = os.toByteArray();

        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);

        ECPrivateKeyParameters cipherParams = new ECPrivateKeyParameters(key.getS(), ecDomainParameters);
        sm2Engine.init(false, cipherParams);

        byte[] decrypted = sm2Engine.processBlock(pms, 0, pms.length);
        return decrypted;
    }

    private static byte[] join(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static void hmacHash(byte[] secret, byte[] seed, byte[] output)
            throws InvalidKeyException, NoSuchAlgorithmException, ShortBufferException, IllegalStateException {
        KeyParameter keyParameter = new KeyParameter(secret);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);

        byte[] a = seed;

        int macSize = mac.getMacSize();

        byte[] b1 = new byte[macSize];
        byte[] b2 = new byte[macSize];

        int pos = 0;
        while (pos < output.length) {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, pos, Math.min(macSize, output.length - pos));
            pos += macSize;
        }
    }

    /**
     * PRF实现
     * 
     * @throws IOException
     * @throws IllegalStateException
     * @throws ShortBufferException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] prf(byte[] secret, byte[] label, byte[] seed, int length) throws IOException,
            InvalidKeyException, NoSuchAlgorithmException, ShortBufferException, IllegalStateException {
        byte[] labelSeed = join(label, seed);
        byte[] result = new byte[length];
        hmacHash(secret, labelSeed, result);
        return result;
    }

    public static byte[] hash(byte[] bytes) {
        Digest digest = new SM3Digest();
        byte[] output = new byte[digest.getDigestSize()];
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(output, 0);
        return output;
    }
}
