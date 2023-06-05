package com.aliyun.gmsse.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLException;
import javax.net.ssl.X509KeyManager;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.aliyun.gmsse.AlertException;
import com.aliyun.gmsse.CipherSuite;
import com.aliyun.gmsse.ClientRandom;
import com.aliyun.gmsse.CompressionMethod;
import com.aliyun.gmsse.ConnectionContext;
import com.aliyun.gmsse.GMSSLContextSpi;
import com.aliyun.gmsse.GMSSLSession;
import com.aliyun.gmsse.GMSSLSocket;
import com.aliyun.gmsse.ProtocolVersion;
import com.aliyun.gmsse.Record;
import com.aliyun.gmsse.SSLConfiguration;
import com.aliyun.gmsse.SecurityParameters;
import com.aliyun.gmsse.Util;
import com.aliyun.gmsse.GMSSLSession.ID;
import com.aliyun.gmsse.handshake.ClientHello;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.Record.ContentType;
import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.handshake.Certificate;
import com.aliyun.gmsse.handshake.CertificateVerify;
import com.aliyun.gmsse.handshake.ClientKeyExchange;
import com.aliyun.gmsse.handshake.Finished;
import com.aliyun.gmsse.handshake.ServerHello;
import com.aliyun.gmsse.handshake.ServerHelloDone;
import com.aliyun.gmsse.handshake.ServerKeyExchange;
import com.aliyun.gmsse.record.Alert;
import com.aliyun.gmsse.record.ChangeCipherSpec;

public class ServerConnectionContext extends ConnectionContext {

    private SecurityParameters securityParameters = new SecurityParameters();
    List<Handshake> handshakes = new ArrayList<Handshake>();

    public ServerConnectionContext(GMSSLContextSpi context, GMSSLSocket socket) {
        super(context, socket, new SSLConfiguration(context, false));
    }

    public ServerConnectionContext(GMSSLContextSpi context, GMSSLSocket socket, SSLConfiguration sslConfig) {
        super(context, socket, sslConfig);
    }

    public ID sessionId;
    public int peerPort;
    public boolean peerVerified;
    public String peerHost;
    public CipherSuite cipherSuite;
    public X509Certificate[] peerCerts;
    public boolean isNegotiated = false;

    public void kickstart() throws IOException {
        // recive ClientHello
        receiveClientHello();

        // send ServerHello
        sendServerHello();

        // send ServerCertificate
        sendServerCertificate();

        // send ServerKeyExchange
        sendServerKeyExchange();

        // recive ServerHelloDone
        sendServerHelloDone();

        // recive ClientKeyExchange
        receiveClientKeyExchange();

        // recive ChangeCipherSpec
        receiveChangeCipherSpec();

        // recive Finished
        receiveFinished();

        // send ChangeCipherSpec
        sendChangeCipherSpec();

        // send finished
        sendFinished();

        this.isNegotiated = true;
    }

    private void receiveClientKeyExchange() throws IOException {
        Record rc = socket.recordStream.read();
        if (rc.contentType != Record.ContentType.HANDSHAKE) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.UNEXPECTED_MESSAGE);
            throw new AlertException(alert, true);
        }

        Handshake hsf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ClientKeyExchange che = (ClientKeyExchange) hsf.body;
        handshakes.add(hsf);

        // 取出加密的 pre_master_secret
        byte[] encryptedPreMasterSecret = che.getEncryptedPreMasterSecret();
        PrivateKey key = sslContext.getKeyManager().getPrivateKey("enc");

        // 通过加密私钥解密 pre_master_secret
        byte[] preMasterSecret;
        try {
            preMasterSecret = Crypto.decrypt((BCECPrivateKey)key, encryptedPreMasterSecret);
        } catch (Exception e) {
            throw new SSLException("decrypt pre master secret failed", e);
        }

        // 计算 masterSecret
        byte[] MASTER_SECRET = "master secret".getBytes();
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(securityParameters.clientRandom);
        os.write(securityParameters.serverRandom);
        byte[] seed = os.toByteArray();
        try {
            securityParameters.masterSecret = Crypto.prf(preMasterSecret, MASTER_SECRET, seed, preMasterSecret.length);
        } catch (Exception ex) {
            throw new SSLException("caculate master secret failed", ex);
        }

        // key_block = PRF(SecurityParameters.master_secret，"keyexpansion"，
        // SecurityParameters.server_random +SecurityParameters.client_random);
        // new TLSKeyMaterialSpec(masterSecret, TLSKeyMaterialSpec.KEY_EXPANSION,
        // key_block.length, server_random, client_random))
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(securityParameters.serverRandom);
        baos.write(securityParameters.clientRandom);
        byte[] keyBlockSeed = baos.toByteArray();
        byte[] keyBlock = null;
        try {
            keyBlock = Crypto.prf(securityParameters.masterSecret, "key expansion".getBytes(), keyBlockSeed, 128);
        } catch (Exception e) {
            throw new SSLException("caculate key block failed", e);
        }

        // client_write_MAC_secret[SecurityParameters.hash_size]
        // server_write_MAC_secret[SecurityParameters.hash_size]
        // client_write_key[SecurityParameters.key_material_length]
        // server_write_key[SecurityParameters.key_material_length]
        // clientWriteIV
        // serverWriteIV

        // client mac key
        byte[] clientMacKey = new byte[32];
        System.arraycopy(keyBlock, 0, clientMacKey, 0, 32);
        socket.recordStream.setDecryptMacKey(clientMacKey);

        // server mac key
        byte[] serverMacKey = new byte[32];
        System.arraycopy(keyBlock, 32, serverMacKey, 0, 32);
        socket.recordStream.setEncryptMacKey(serverMacKey);

        // client write key
        byte[] clientWriteKey = new byte[16];
        System.arraycopy(keyBlock, 64, clientWriteKey, 0, 16);
        SM4Engine readCipher = new SM4Engine();
        readCipher.init(false, new KeyParameter(clientWriteKey));
        socket.recordStream.setReadCipher(readCipher);

        // server write key
        byte[] serverWriteKey = new byte[16];
        System.arraycopy(keyBlock, 80, serverWriteKey, 0, 16);
        SM4Engine writeCipher = new SM4Engine();
        writeCipher.init(true, new KeyParameter(serverWriteKey));
        socket.recordStream.setWriteCipher(writeCipher);

        // client write iv
        byte[] clientWriteIV = new byte[16];
        System.arraycopy(keyBlock, 96, clientWriteIV, 0, 16);
        socket.recordStream.setDecryptIV(clientWriteIV);

        // server write iv
        byte[] serverWriteIV = new byte[16];
        System.arraycopy(keyBlock, 112, serverWriteIV, 0, 16);
        socket.recordStream.setEncryptIV(serverWriteIV);
    }

    private void sendServerHelloDone() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ServerHelloDone shd = new ServerHelloDone();
        Handshake hs = new Handshake(Handshake.Type.SERVER_HELLO_DONE, shd);
        Record rc = new Record(Record.ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);
    }

    private void sendServerKeyExchange() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        try {
            // see https://github.com/Tongsuo-Project/Tongsuo/blob/master/ssl/statem_ntls/ntls_statem_srvr.c#L1630
            Signature signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
            SM2ParameterSpec spec = new SM2ParameterSpec("1234567812345678".getBytes());
            signature.setParameter(spec);
            PrivateKey signKey = sslContext.getKeyManager().getPrivateKey("sign");
            signature.initSign(signKey);
            signature.update(securityParameters.clientRandom);
            signature.update(securityParameters.serverRandom);

            X509Certificate[] encryptCerts = sslContext.getKeyManager().getCertificateChain("enc");
            byte[] encryptCert = encryptCerts[0].getEncoded();
            int length = encryptCert.length;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write((length >>> 16) & 0xff);
            baos.write((length >>> 8) & 0xff);
            baos.write(length & 0xff);
            baos.write(encryptCert);
            signature.update(baos.toByteArray());
            ServerKeyExchange ske = new ServerKeyExchange(signature.sign());
            Handshake hs = new Handshake(Handshake.Type.SERVER_KEY_EXCHANGE, ske);
            Record rc = new Record(Record.ContentType.HANDSHAKE, version, hs.getBytes());
            socket.recordStream.write(rc);
            handshakes.add(hs);
        } catch (Exception e2) {
            throw new SSLException("server key exchange signature fails!", e2);
        }
    }

    private void sendServerCertificate() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        X509KeyManager km = sslContext.getKeyManager();
        X509Certificate[] signCerts = km.getCertificateChain("sign");
        X509Certificate[] encCerts = km.getCertificateChain("enc");
        Certificate cert = new Certificate(new X509Certificate[] {
            signCerts[0],
            encCerts[0]
        });
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE, cert);
        Record rc = new Record(Record.ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);
    }

    private void sendServerHello() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        int gmtUnixTime = (int) (System.currentTimeMillis() / 1000L);
        byte[] randomBytes = sslContext.getSecureRandom().generateSeed(28);
        ClientRandom random = new ClientRandom(gmtUnixTime, randomBytes);
        byte[] sessionId = new byte[32];
        sslContext.getSecureRandom().nextBytes(sessionId);

        CompressionMethod method = CompressionMethod.NULL;
        ServerHello sh = new ServerHello(version, random.getBytes(), sessionId, CipherSuite.NTLS_SM2_WITH_SM4_SM3, method);
        securityParameters.serverRandom = sh.getRandom();
        Handshake hs = new Handshake(Handshake.Type.SERVER_HELLO, sh);
        Record rc = new Record(Record.ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);
    }

    private void receiveClientHello() throws IOException {
        Record rc = socket.recordStream.read();
        if (rc.contentType != Record.ContentType.HANDSHAKE) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.UNEXPECTED_MESSAGE);
            throw new AlertException(alert, true);
        }

        Handshake hs = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ClientHello ch = (ClientHello) hs.body;

        // TODO: check the version, cipher suite, compression methods
        ProtocolVersion version = ch.getProtocolVersion();
        ch.getCipherSuites();
        ch.getCompressionMethods();
        ch.getSessionId();

        securityParameters.clientRandom = ch.getClientRandom().getBytes();
        handshakes.add(hs);
    }

    private void receiveFinished() throws IOException {
        Record rc = socket.recordStream.read(true);
        Handshake hs = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Finished finished = (Finished) hs.body;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Handshake handshake : handshakes) {
            out.write(handshake.getBytes());
        }
        // SM3(handshake_mesages)
        byte[] seed = Crypto.hash(out.toByteArray());
        byte[] verifyData;
        try {
            // PRF(master_secret，finished_label，SM3(handshake_mesages))[0.11]
            verifyData = Crypto.prf(securityParameters.masterSecret, "client finished".getBytes(), seed, 12);
        } catch (Exception e) {
            throw new SSLException("caculate verify data failed", e);
        }

        if (!Arrays.equals(finished.getBytes(), verifyData)) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.HANDSHAKE_FAILURE);
            throw new AlertException(alert, true);
        }

        handshakes.add(hs);
    }

    private void receiveChangeCipherSpec() throws IOException {
        Record rc = socket.recordStream.read();
        ChangeCipherSpec ccs = ChangeCipherSpec.read(new ByteArrayInputStream(rc.fragment));
    }

    private void sendFinished() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Handshake handshake : handshakes) {
            out.write(handshake.getBytes());
        }
        // SM3(handshake_mesages)
        byte[] seed = Crypto.hash(out.toByteArray());
        byte[] verifyData;
        try {
            // PRF(master_secret，finished_label，SM3(handshake_mesages))[0.11]
            verifyData = Crypto.prf(securityParameters.masterSecret, "server finished".getBytes(), seed, 12);
        } catch (Exception e) {
            throw new SSLException("caculate verify data failed", e);
        }

        Finished finished = new Finished(verifyData);
        Handshake hs = new Handshake(Handshake.Type.FINISHED, finished);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc, true);
        handshakes.add(hs);
    }

    private void sendChangeCipherSpec() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        Record rc = new Record(ContentType.CHANGE_CIPHER_SPEC, version, new ChangeCipherSpec().getBytes());
        socket.recordStream.write(rc);
    }

}
