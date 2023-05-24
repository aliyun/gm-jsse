package com.aliyun.gmsse;

import com.aliyun.gmsse.Record.ContentType;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
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
    private boolean needAuthClient = false;
    private Socket underlyingSocket;
    private boolean autoClose;
    private boolean isConnected = false;

    // raw socket in/out
    private InputStream socketIn;
    private OutputStream socketOut;
    public RecordStream recordStream;
    private final AppDataInputStream appInput = new AppDataInputStream();
    private final AppDataOutputStream appOutput = new AppDataOutputStream();

    private final GMSSLContextSpi context;
    private ConnectionContext connection;

    public GMSSLSocket(GMSSLContextSpi context, String host, int port) throws IOException {
        super(host, port);
        remoteHost = host;
        this.context = context;
        this.connection = new ConnectionContext(context, this, true);
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
        this.connection = new ConnectionContext(context, this, true);
        ensureConnect();
        this.isConnected = true;
    }

    public GMSSLSocket(GMSSLContextSpi context, Socket socket, String host, int port, boolean autoClose) throws IOException {
        underlyingSocket = socket;
        remoteHost = host;
        this.autoClose = autoClose;
        this.context = context;
        this.connection = new ConnectionContext(context, this, true);
        ensureConnect();
        this.isConnected = true;
    }

    public GMSSLSocket(GMSSLContextSpi context, String host, int port, InetAddress localAddr, int localPort) throws IOException {
        bind(new InetSocketAddress(localAddr, localPort));
        SocketAddress socketAddress = host != null ? new InetSocketAddress(host, port) :
               new InetSocketAddress(InetAddress.getByName(null), port);
        remoteHost = host;
        this.context = context;
        this.connection = new ConnectionContext(context, this, true);
        connect(socketAddress, 0);
        ensureConnect();
        this.isConnected = true;
    }

    public GMSSLSocket(GMSSLContextSpi context, InetAddress host, int port, InetAddress localAddress, int localPort) throws IOException {
        bind(new InetSocketAddress(localAddress, localPort));
        SocketAddress socketAddress = new InetSocketAddress(host, port);
        remoteHost = host.getHostName();
        if (remoteHost == null) {
            remoteHost = host.getHostAddress();
        }
        this.context = context;
        this.connection = new ConnectionContext(context, this, true);
        connect(socketAddress, 0);
        ensureConnect();
        this.isConnected = true;
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
        return (connection.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED);
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
        return (connection.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED);
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
        connection.sslConfig.clientAuthType = (need ? ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE);
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

        connection.kickstart();
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
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }

        if (!isConnected) {
            throw new SocketException("Socket is not connected");
        }

        return appOutput;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }

        if (!isConnected) {
            throw new SocketException("Socket is not connected");
        }

        return appInput;
    }

    private class AppDataInputStream extends InputStream {

        private byte[] cacheBuffer = null;
        private int cachePos = 0;

        public AppDataInputStream() {}

        @Override
        public int read() throws IOException {
            byte[] buf = new byte[1];
            int ret = read(buf, 0, 1);
            return ret < 0 ? -1 : buf[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException("the target buffer is null");
            }

            if (len == 0) {
                return 0;
            }

            if (!connection.isNegotiated) {
                startHandshake();
            }

            int length;
            if (cacheBuffer != null) {
                length = Math.min(cacheBuffer.length - cachePos, len);
                System.arraycopy(cacheBuffer, cachePos, b, off, length);

                cachePos += length;
                if (cachePos >= cacheBuffer.length) {
                    cacheBuffer = null;
                    cachePos = 0;
                }
            } else {
                Record record = recordStream.read(true);
                length = Math.min(record.fragment.length, len);
                System.arraycopy(record.fragment, 0, b, off, length);
                if (length < record.fragment.length) {
                    cacheBuffer = record.fragment;
                    cachePos = len;
                }
            }
            return length;
        }
    }

    private class AppDataOutputStream extends OutputStream {

        public AppDataOutputStream() {}

        @Override
        public void write(int b) throws IOException {
            write(new byte[] { (byte) b }, 0, 1);
        }

        @Override
        public void write(byte b[], int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException();
            } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length) || ((off + len) < 0)) {
                throw new IndexOutOfBoundsException();
            } else if (len == 0) {
                return;
            }

            if (!connection.isNegotiated) {
                startHandshake();
            }

            ProtocolVersion version = ProtocolVersion.NTLS_1_1;
            byte[] content = new byte[len];
            System.arraycopy(b, off, content, 0, len);
            Record recored = new Record(ContentType.APPLICATION_DATA, version, content);
            recordStream.write(recored, true);
        }

        @Override
        public void flush() throws IOException {
            recordStream.flush();
        }

    }

    public String getPeerHost() {
        return remoteHost;
    }
}
