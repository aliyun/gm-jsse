package com.aliyun.gmsse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLException;
import javax.net.ssl.X509KeyManager;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

public class ConnectionContext {

    private GMSSLContextSpi sslContext;
    private SecurityParameters securityParameters = new SecurityParameters();
    List<Handshake> handshakes = new ArrayList<Handshake>();
    private GMSSLSocket socket;

    public ConnectionContext(GMSSLContextSpi context, GMSSLSocket socket, boolean isClientMode) {
        this.sslContext = context;
        this.socket = socket;
        this.sslConfig = new SSLConfiguration(context, isClientMode);
        this.session = new GMSSLSession();
    }

    public ConnectionContext(GMSSLContextSpi context, GMSSLSocket socket, SSLConfiguration sslConfig) {
        this.sslContext = context;
        this.sslConfig = sslConfig;
        this.socket = socket;
        this.session = new GMSSLSession();
    }

    public SSLConfiguration sslConfig;
    public ID sessionId;
    public int peerPort;
    public boolean peerVerified;
    public String peerHost;
    public CipherSuite cipherSuite;
    public X509Certificate[] peerCerts;
    public GMSSLSession session;
    public boolean isNegotiated = false;

    public void kickstart() throws IOException {

        if (sslConfig.isClientMode) {
            // send ClientHello
            sendClientHello();

            // recive ServerHello
            receiveServerHello();

            // recive ServerCertificate
            receiveServerCertificate();

            // recive ServerKeyExchange
            receiveServerKeyExchange();

            // recive ServerHello
            receiveServerHelloDone();

            // send ClientKeyExchange
            sendClientKeyExchange();

            // send ChangeCipherSpec
            sendChangeCipherSpec();

            // send Finished
            sendFinished();

            // recive ChangeCipherSpec
            receiveChangeCipherSpec();

            // recive finished
            receiveFinished();

            this.isNegotiated = true;
        } else {
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
        }
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

        // byte[] encryptedPreMasterSecret = che.getEncryptedPreMasterSecret();

        // PrivateKey key = sslContext.getKeyManager().getPrivateKey("enc");

        // // 计算 masterSecret
        // byte[] MASTER_SECRET = "master secret".getBytes();
        // ByteArrayOutputStream os = new ByteArrayOutputStream();
        // os.write(securityParameters.clientRandom);
        // os.write(securityParameters.serverRandom);
        // byte[] seed = os.toByteArray();
        // try {
        //     securityParameters.masterSecret = Crypto.prf(preMasterSecret, MASTER_SECRET, seed, preMasterSecret.length);
        // } catch (Exception ex) {
        //     throw new SSLException("caculate master secret failed", ex);
        // }

        // // key_block = PRF(SecurityParameters.master_secret，"keyexpansion"，
        // // SecurityParameters.server_random +SecurityParameters.client_random);
        // // new TLSKeyMaterialSpec(masterSecret, TLSKeyMaterialSpec.KEY_EXPANSION,
        // // key_block.length, server_random, client_random))
        // ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // baos.write(securityParameters.serverRandom);
        // baos.write(securityParameters.clientRandom);
        // byte[] keyBlockSeed = baos.toByteArray();
        // byte[] keyBlock = null;
        // try {
        //     keyBlock = Crypto.prf(securityParameters.masterSecret, "key expansion".getBytes(), keyBlockSeed, 128);
        // } catch (Exception e) {
        //     throw new SSLException("caculate key block failed", e);
        // }

        // // client_write_MAC_secret[SecurityParameters.hash_size]
        // // server_write_MAC_secret[SecurityParameters.hash_size]
        // // client_write_key[SecurityParameters.key_material_length]
        // // server_write_key[SecurityParameters.key_material_length]
        // // clientWriteIV
        // // serverWriteIV

        // // client mac key
        // byte[] clientMacKey = new byte[32];
        // System.arraycopy(keyBlock, 0, clientMacKey, 0, 32);
        // socket.recordStream.setClientMacKey(clientMacKey);

        // // server mac key
        // byte[] serverMacKey = new byte[32];
        // System.arraycopy(keyBlock, 32, serverMacKey, 0, 32);
        // socket.recordStream.setServerMacKey(serverMacKey);

        // // client write key
        // byte[] clientWriteKey = new byte[16];
        // System.arraycopy(keyBlock, 64, clientWriteKey, 0, 16);
        // SM4Engine writeCipher = new SM4Engine();
        // writeCipher.init(true, new KeyParameter(clientWriteKey));
        // socket.recordStream.setWriteCipher(writeCipher);

        // // server write key
        // byte[] serverWriteKey = new byte[16];
        // System.arraycopy(keyBlock, 80, serverWriteKey, 0, 16);
        // SM4Engine readCipher = new SM4Engine();
        // readCipher.init(false, new KeyParameter(serverWriteKey));
        // socket.recordStream.setReadCipher(readCipher);

        // // client write iv
        // byte[] clientWriteIV = new byte[16];
        // System.arraycopy(keyBlock, 96, clientWriteIV, 0, 16);
        // socket.recordStream.setClientWriteIV(clientWriteIV);

        // // server write iv
        // byte[] serverWriteIV = new byte[16];
        // System.arraycopy(keyBlock, 112, serverWriteIV, 0, 16);
        // socket.recordStream.setServerWriteIV(serverWriteIV);
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

        Handshake hsf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ClientHello ch = (ClientHello) hsf.body;

        // TODO: check the version, cipher suite, compression methods
        ProtocolVersion version = ch.getProtocolVersion();
        ch.getCipherSuites();
        ch.getCompressionMethods();
        ch.getSessionId();

        securityParameters.clientRandom = ch.getClientRandom().getBytes();
        handshakes.add(hsf);
    }

    private void receiveFinished() throws IOException {
        Record rc = socket.recordStream.read(true);
        Handshake hs = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Finished finished = (Finished) hs.body;
        Finished serverFinished = new Finished(securityParameters.masterSecret, "server finished", handshakes);
        if (!Arrays.equals(finished.getBytes(), serverFinished.getBytes())) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.HANDSHAKE_FAILURE);
            throw new AlertException(alert, true);
        }
    }

    private void receiveChangeCipherSpec() throws IOException {
        Record rc = socket.recordStream.read();
        ChangeCipherSpec ccs = ChangeCipherSpec.read(new ByteArrayInputStream(rc.fragment));
    }

    private void sendFinished() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        Finished finished = new Finished(securityParameters.masterSecret, "client finished", handshakes);
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

    private void sendCertificateVerify(List<Handshake> handshakes) throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        CertificateVerify cv = new CertificateVerify(handshakes);
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE_VERIFY, cv);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);
    }

    private void sendClientKeyExchange() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        // 计算 preMasterSecret
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        ba.write(version.getMajor());
        ba.write(version.getMinor());
        ba.write(sslContext.getSecureRandom().generateSeed(46));
        byte[] preMasterSecret = ba.toByteArray();

        // 计算 encryptedPreMasterSecret
        byte[] encryptedPreMasterSecret;
        try {
            encryptedPreMasterSecret = Crypto.encrypt((BCECPublicKey) securityParameters.encryptionCert.getPublicKey(), preMasterSecret);
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        ClientKeyExchange ckex = new ClientKeyExchange(encryptedPreMasterSecret);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_KEY_EXCHANGE, ckex);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);

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
        socket.recordStream.setClientMacKey(clientMacKey);

        // server mac key
        byte[] serverMacKey = new byte[32];
        System.arraycopy(keyBlock, 32, serverMacKey, 0, 32);
        socket.recordStream.setServerMacKey(serverMacKey);

        // client write key
        byte[] clientWriteKey = new byte[16];
        System.arraycopy(keyBlock, 64, clientWriteKey, 0, 16);
        SM4Engine writeCipher = new SM4Engine();
        writeCipher.init(true, new KeyParameter(clientWriteKey));
        socket.recordStream.setWriteCipher(writeCipher);

        // server write key
        byte[] serverWriteKey = new byte[16];
        System.arraycopy(keyBlock, 80, serverWriteKey, 0, 16);
        SM4Engine readCipher = new SM4Engine();
        readCipher.init(false, new KeyParameter(serverWriteKey));
        socket.recordStream.setReadCipher(readCipher);

        // client write iv
        byte[] clientWriteIV = new byte[16];
        System.arraycopy(keyBlock, 96, clientWriteIV, 0, 16);
        socket.recordStream.setClientWriteIV(clientWriteIV);

        // server write iv
        byte[] serverWriteIV = new byte[16];
        System.arraycopy(keyBlock, 112, serverWriteIV, 0, 16);
        socket.recordStream.setServerWriteIV(serverWriteIV);
    }

    private void sendClientCertificate() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        X509Certificate[] certs = session.keyManager.getCertificateChain(socket.getPeerHost());
        Certificate cert = new Certificate(certs);
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE, cert);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
    }

    private void receiveServerHelloDone() throws IOException {
        Record rc = socket.recordStream.read();
        Handshake shdf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        handshakes.add(shdf);
    }

    private void receiveServerKeyExchange() throws IOException {
        Record rc = socket.recordStream.read();
        Handshake skef = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ServerKeyExchange ske = (ServerKeyExchange) skef.body;
        // signature cert
        X509Certificate signCert = session.peerCerts[0];
        // encryption cert
        X509Certificate encryptionCert = session.peerCerts[1];
        // verify the signature
        boolean verified = false;

        try {
            verified = ske.verify(signCert.getPublicKey(), securityParameters.clientRandom,
                    securityParameters.serverRandom, encryptionCert);
        } catch (Exception e2) {
            throw new SSLException("server key exchange verify fails!", e2);
        }

        if (!verified) {
            throw new SSLException("server key exchange verify fails!");
        }

        handshakes.add(skef);
        securityParameters.encryptionCert = encryptionCert;
    }

    private void receiveServerCertificate() throws IOException {
        Record rc = socket.recordStream.read();
        Handshake cf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Certificate cert = (Certificate) cf.body;
        X509Certificate[] peerCerts = cert.getCertificates();
        try {
            sslContext.getTrustManager().checkServerTrusted(peerCerts, session.cipherSuite.getAuthType());
        } catch (CertificateException e) {
            throw new SSLException("could not verify peer certificate!", e);
        }
        session.peerCerts = peerCerts;
        session.peerVerified = true;
        handshakes.add(cf);
    }

    private void receiveServerHello() throws IOException {
        Record rc = socket.recordStream.read();
        if (rc.contentType != Record.ContentType.HANDSHAKE) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.UNEXPECTED_MESSAGE);
            throw new AlertException(alert, true);
        }
        Handshake hsf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ServerHello sh = (ServerHello) hsf.body;
        sh.getCompressionMethod();
        // TODO: process the compresion method
        session.cipherSuite = sh.getCipherSuite();
        session.peerHost = socket.getPeerHost();
        session.peerPort = socket.getPort();
        session.sessionId = new GMSSLSession.ID(sh.getSessionId());
        handshakes.add(hsf);
        securityParameters.serverRandom = sh.getRandom();
    }

    private void sendClientHello() throws IOException {
        byte[] sessionId = new byte[0];
        int gmtUnixTime = (int) (System.currentTimeMillis() / 1000L);
        ClientRandom random = new ClientRandom(gmtUnixTime, sslContext.getSecureRandom().generateSeed(28));
        List<CipherSuite> suites = sslContext.getSupportedCipherSuites();
        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>(2);
        compressions.add(CompressionMethod.NULL);
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ClientHello ch = new ClientHello(version, random, sessionId, suites, compressions);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_HELLO, ch);
        Record rc = new Record(Record.ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);
        securityParameters.clientRandom = random.getBytes();
    }

}
