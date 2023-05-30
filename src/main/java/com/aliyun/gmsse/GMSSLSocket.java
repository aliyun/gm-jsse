package com.aliyun.gmsse;

import com.aliyun.gmsse.Record.ContentType;
import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.handshake.Certificate;
import com.aliyun.gmsse.handshake.ClientHello;
import com.aliyun.gmsse.handshake.ClientKeyExchange;
import com.aliyun.gmsse.handshake.Finished;
import com.aliyun.gmsse.handshake.ServerHello;
import com.aliyun.gmsse.handshake.ServerKeyExchange;
import com.aliyun.gmsse.record.Alert;
import com.aliyun.gmsse.record.AppDataInputStream;
import com.aliyun.gmsse.record.AppDataOutputStream;
import com.aliyun.gmsse.record.ChangeCipherSpec;
import com.aliyun.gmsse.record.Handshake;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * GMSSLSocket
 */
public class GMSSLSocket extends SSLSocket {

    BufferedOutputStream handshakeOut;
    int port;
    public SSLSessionContext sessionContext;
    private String remoteHost;
    private boolean clientMode;
    private Socket underlyingSocket;
    private int underlyingPort;
    private boolean autoClose;
    private boolean isConnected = false;
    private boolean isNegotiated = false;

    // raw socket in/out
    private InputStream socketIn;
    private OutputStream socketOut;
    private RecordStream recordStream;

    private SecurityParameters securityParameters = new SecurityParameters();
    List<Handshake> handshakes = new ArrayList<Handshake>();
    private final GMSSLContextSpi context;
    private ConnectionContext connection;

    public GMSSLSocket(GMSSLContextSpi context, String host, int port) throws IOException {
        super(host, port);
        remoteHost = host;
        this.context = context;
        this.connection = new ConnectionContext(context, true);
        ensureConnect();
        this.isConnected = true;
    }

    public GMSSLSocket(GMSSLContextSpi context, InetAddress host, int port) throws IOException {
        super(host, port);
        remoteHost = host.getHostName();
        if (remoteHost == null) {
            remoteHost = host.getHostAddress();
        }
        this.context = context;
        this.connection = new ConnectionContext(context, true);
        ensureConnect();
        this.isConnected = true;
    }

    public GMSSLSocket(GMSSLContextSpi context, Socket socket, String host, int port, boolean autoClose) throws IOException {
        underlyingSocket = socket;
        remoteHost = host;
        underlyingPort = port;
        this.autoClose = autoClose;
        this.context = context;
        this.connection = new ConnectionContext(context, true);
        ensureConnect();
        this.isConnected = true;
    }

    public GMSSLSocket(GMSSLContextSpi context, String host, int port, InetAddress localAddr, int localPort) throws IOException {
        bind(new InetSocketAddress(localAddr, localPort));
        SocketAddress socketAddress = host != null ? new InetSocketAddress(host, port) :
               new InetSocketAddress(InetAddress.getByName(null), port);
        remoteHost = host;
        this.context = context;
        this.connection = new ConnectionContext(context, true);
        connect(socketAddress, 0);
        ensureConnect();
        this.isConnected = true;
        startHandshake();
    }

    public GMSSLSocket(GMSSLContextSpi context, InetAddress host, int port, InetAddress localAddress, int localPort) throws IOException {
        bind(new InetSocketAddress(localAddress, localPort));
        SocketAddress socketAddress = new InetSocketAddress(host, port);
        remoteHost = host.getHostName();
        if (remoteHost == null) {
            remoteHost = host.getHostAddress();
        }
        this.context = context;
        this.connection = new ConnectionContext(context, true);
        connect(socketAddress, 0);
        ensureConnect();
        this.isConnected = true;
        startHandshake();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public boolean getEnableSessionCreation() {
        return connection.sslConfig.enableSessionCreation;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(connection.sslConfig.enabledCipherSuites);
    }

    @Override
    public String[] getEnabledProtocols() {
        return ProtocolVersion.toStringArray(connection.sslConfig.enabledProtocols);
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public SSLSession getSession() {
        return connection.session;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(context.getSupportedCipherSuites());
    }

    @Override
    public String[] getSupportedProtocols() {
        return ProtocolVersion.toStringArray(context.getSupportedProtocolVersions());
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        connection.sslConfig.enableSessionCreation = flag;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        if (suites == null || suites.length == 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < suites.length; i++) {
            if (CipherSuite.forName(suites[i]) == null) {
                throw new IllegalArgumentException("unsupported suite: " + suites[i]);
            }
        }

        List<CipherSuite> cipherSuites = new ArrayList<>(suites.length);
        for (int i = 0; i < suites.length; i++) {
            CipherSuite suite = CipherSuite.forName(suites[i]);
            cipherSuites.add(suite);
        }

        connection.sslConfig.enabledCipherSuites = cipherSuites;
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        if (protocols == null || protocols.length == 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < protocols.length; i++) {
            if (!(protocols[i].equalsIgnoreCase("NTLSv1.1"))) {
                throw new IllegalArgumentException("unsupported protocol: " + protocols[i]);
            }
        }

        List<ProtocolVersion> enabledProtocols = new ArrayList<>(protocols.length);
        for (int i = 0; i < protocols.length; i++) {
            enabledProtocols.add(ProtocolVersion.NTLS_1_1);
        }
        connection.sslConfig.enabledProtocols = enabledProtocols;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
    }

    @Override
    public void setUseClientMode(boolean mode) {
        clientMode = mode;
    }

    @Override
    public void setWantClientAuth(boolean want) {
    }

    @Override
    public void startHandshake() throws IOException {
        if (!isConnected) {
            throw new SocketException("Socket is not connected");
        }

        // send ClientHello
        sendClientHello();

        // recive ServerHello
        receiveServerHello();

        // recive ServerCertificate
        receiveServerCertificate();

        // recive ServerKeyExchange
        receiveServerKeyExchange();

        // recive ServerHelloDone
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
    }

    private void receiveFinished() throws IOException {
        Record rc = recordStream.read(true);
        Handshake hs = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Finished finished = (Finished) hs.body;
        Finished serverFinished = new Finished(securityParameters.masterSecret, "server finished", handshakes);
        if (!Arrays.equals(finished.getBytes(), serverFinished.getBytes())) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.HANDSHAKE_FAILURE);
            throw new AlertException(alert, true);
        }
    }

    private void receiveChangeCipherSpec() throws IOException {
        Record rc = recordStream.read();
        ChangeCipherSpec ccs = ChangeCipherSpec.read(new ByteArrayInputStream(rc.fragment));
    }

    private void sendFinished() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        Finished finished = new Finished(securityParameters.masterSecret, "client finished", handshakes);
        Handshake hs = new Handshake(Handshake.Type.FINISHED, finished);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        recordStream.write(rc, true);
        handshakes.add(hs);
    }

    private void sendChangeCipherSpec() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        Record rc = new Record(ContentType.CHANGE_CIPHER_SPEC, version, new ChangeCipherSpec().getBytes());
        recordStream.write(rc);
    }

    private void sendClientKeyExchange() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ClientKeyExchange ckex = new ClientKeyExchange(version, context.getSecureRandom(), securityParameters.encryptionCert);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_KEY_EXCHANGE, ckex);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
        try {
            securityParameters.masterSecret = ckex.getMasterSecret(securityParameters.clientRandom,
                    securityParameters.serverRandom);
        } catch (Exception e) {
            e.printStackTrace();
            throw new SSLException("caculate master secret failed", e);
        }

        // key_block = PRF(SecurityParameters.master_secret，"keyexpansion"，
        // SecurityParameters.server_random +SecurityParameters.client_random);
        // new TLSKeyMaterialSpec(masterSecret, TLSKeyMaterialSpec.KEY_EXPANSION,
        // key_block.length, server_random, client_random))
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(securityParameters.serverRandom);
        os.write(securityParameters.clientRandom);
        byte[] seed = os.toByteArray();
        byte[] keyBlock = null;
        try {
            keyBlock = Crypto.prf(securityParameters.masterSecret, "key expansion".getBytes(), seed, 128);
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
        recordStream.setClientMacKey(clientMacKey);

        // server mac key
        byte[] serverMacKey = new byte[32];
        System.arraycopy(keyBlock, 32, serverMacKey, 0, 32);
        recordStream.setServerMacKey(serverMacKey);

        // client write key
        byte[] clientWriteKey = new byte[16];
        System.arraycopy(keyBlock, 64, clientWriteKey, 0, 16);
        SM4Engine writeCipher = new SM4Engine();
        writeCipher.init(true, new KeyParameter(clientWriteKey));
        recordStream.setWriteCipher(writeCipher);

        // server write key
        byte[] serverWriteKey = new byte[16];
        System.arraycopy(keyBlock, 80, serverWriteKey, 0, 16);
        SM4Engine readCipher = new SM4Engine();
        readCipher.init(false, new KeyParameter(serverWriteKey));
        recordStream.setReadCipher(readCipher);

        // client write iv
        byte[] clientWriteIV = new byte[16];
        System.arraycopy(keyBlock, 96, clientWriteIV, 0, 16);
        recordStream.setClientWriteIV(clientWriteIV);

        // server write iv
        byte[] serverWriteIV = new byte[16];
        System.arraycopy(keyBlock, 112, serverWriteIV, 0, 16);
        recordStream.setServerWriteIV(serverWriteIV);
    }

    private void receiveServerHelloDone() throws IOException {
        Record rc = recordStream.read();
        Handshake shdf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        handshakes.add(shdf);
    }

    private void receiveServerKeyExchange() throws IOException {
        Record rc = recordStream.read();
        Handshake skef = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ServerKeyExchange ske = (ServerKeyExchange) skef.body;
        // signature cert
        X509Certificate signCert = connection.session.peerCerts[0];
        // encryption cert
        X509Certificate encryptionCert = connection.session.peerCerts[1];
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
        Record rc = recordStream.read();
        Handshake cf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Certificate cert = (Certificate) cf.body;
        X509Certificate[] peerCerts = cert.getCertificates();
        try {
            context.getTrustManager().checkServerTrusted(peerCerts, connection.session.cipherSuite.getAuthType());
        } catch (CertificateException e) {
            throw new SSLException("could not verify peer certificate!", e);
        }
        connection.session.peerCerts = peerCerts;
        connection.session.peerVerified = true;
        handshakes.add(cf);
    }

    private void receiveServerHello() throws IOException {
        Record rc = recordStream.read();
        if (rc.contentType != Record.ContentType.HANDSHAKE) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.UNEXPECTED_MESSAGE);
            throw new AlertException(alert, true);
        }

        Handshake hsf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ServerHello sh = (ServerHello) hsf.body;
        sh.getCompressionMethod();
        // TODO: process the compresion method
        connection.session.cipherSuite = sh.getCipherSuite();
        connection.session.peerHost = remoteHost;
        connection.session.peerPort = port;
        connection.session.sessionId = new GMSSLSession.ID(sh.getSessionId());
        handshakes.add(hsf);
        securityParameters.serverRandom = sh.getRandom();
    }

    private void sendClientHello() throws IOException {
        byte[] sessionId = new byte[0];
        int gmtUnixTime = (int) (System.currentTimeMillis() / 1000L);
        ClientRandom random = new ClientRandom(gmtUnixTime, context.getSecureRandom().generateSeed(28));
        List<CipherSuite> suites = context.getSupportedCipherSuites();
        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>(2);
        compressions.add(CompressionMethod.NULL);
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ClientHello ch = new ClientHello(version, random, sessionId, suites, compressions);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_HELLO, ch);
        Record rc = new Record(Record.ContentType.HANDSHAKE, version, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
        securityParameters.clientRandom = random.getBytes();
    }

    private void ensureConnect() throws IOException {
        if (underlyingSocket != null) {
            if (!underlyingSocket.isConnected()) {
                underlyingSocket.connect(this.getRemoteSocketAddress());
            }
        } else {
            if (!this.isConnected()) {
                SocketAddress socketAddress = new InetSocketAddress(remoteHost, port);
                connect(socketAddress);
            }
        }
        if (underlyingSocket != null) {
            socketIn = underlyingSocket.getInputStream();
            socketOut = underlyingSocket.getOutputStream();
        } else {
            socketIn = super.getInputStream();
            socketOut = super.getOutputStream();
        }
        recordStream = new RecordStream(socketIn, socketOut);
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return new AppDataOutputStream(recordStream);
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new AppDataInputStream(recordStream);
    }
}
