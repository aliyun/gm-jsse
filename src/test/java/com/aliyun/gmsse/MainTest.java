package com.aliyun.gmsse;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.ReadableByteChannel;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.UnrecoverableKeyException;
import java.util.Iterator;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import java.nio.channels.WritableByteChannel;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

public class MainTest {

    public abstract class SSLProvider implements Runnable {
        final SSLEngine engine;
        final Executor ioWorker, taskWorkers;
        final ByteBuffer clientWrap, clientUnwrap;
        final ByteBuffer serverWrap, serverUnwrap;

        public SSLProvider(SSLEngine engine, int capacity, Executor ioWorker, Executor taskWorkers) {
            this.clientWrap = ByteBuffer.allocate(capacity);
            this.serverWrap = ByteBuffer.allocate(capacity);
            this.clientUnwrap = ByteBuffer.allocate(capacity);
            this.serverUnwrap = ByteBuffer.allocate(capacity);
            this.clientUnwrap.limit(0);
            this.engine = engine;
            this.ioWorker = ioWorker;
            this.taskWorkers = taskWorkers;
            this.ioWorker.execute(this);
        }

        public abstract void onInput(ByteBuffer decrypted);

        public abstract void onOutput(ByteBuffer encrypted);

        public abstract void onFailure(Exception ex);

        public abstract void onSuccess();

        public abstract void onClosed();

        public void sendAsync(final ByteBuffer data) {
            this.ioWorker.execute(new Runnable() {
                @Override
                public void run() {
                    clientWrap.put(data);

                    SSLProvider.this.run();
                }
            });
        }

        public void notify(final ByteBuffer data) {
            this.ioWorker.execute(new Runnable() {
                @Override
                public void run() {
                    clientUnwrap.put(data);
                    SSLProvider.this.run();
                }
            });
        }

        public void run() {
            // executes non-blocking tasks on the IO-Worker
            while (this.isHandShaking()) {
                continue;
            }
        }

        private synchronized boolean isHandShaking() {
            switch (engine.getHandshakeStatus()) {
                case NOT_HANDSHAKING:
                    boolean occupied = false; {
                    if (clientWrap.position() > 0)
                        occupied |= this.wrap();
                    if (clientUnwrap.position() > 0)
                        occupied |= this.unwrap();
                }
                    return occupied;

                case NEED_WRAP:
                    if (!this.wrap())
                        return false;
                    break;

                case NEED_UNWRAP:
                    if (!this.unwrap())
                        return false;
                    break;

                case NEED_TASK:
                    final Runnable sslTask = engine.getDelegatedTask();
                    Runnable wrappedTask = new Runnable() {
                        @Override
                        public void run() {
                            sslTask.run();
                            ioWorker.execute(SSLProvider.this);
                        }
                    };
                    taskWorkers.execute(wrappedTask);
                    return false;

                case FINISHED:
                    throw new IllegalStateException("FINISHED");
            }

            return true;
        }

        private boolean wrap() {
            SSLEngineResult wrapResult;

            try {
                clientWrap.flip();
                wrapResult = engine.wrap(clientWrap, serverWrap);
                clientWrap.compact();
            } catch (SSLException exc) {
                this.onFailure(exc);
                return false;
            }

            switch (wrapResult.getStatus()) {
                case OK:
                    if (serverWrap.position() > 0) {
                        serverWrap.flip();
                        this.onOutput(serverWrap);
                        serverWrap.compact();
                    }
                    break;

                case BUFFER_UNDERFLOW:
                    // try again later
                    break;

                case BUFFER_OVERFLOW:
                    throw new IllegalStateException("failed to wrap");

                case CLOSED:
                    this.onClosed();
                    return false;
            }

            return true;
        }

        private boolean unwrap() {
            SSLEngineResult unwrapResult;

            try {
                clientUnwrap.flip();
                unwrapResult = engine.unwrap(clientUnwrap, serverUnwrap);
                clientUnwrap.compact();
            } catch (SSLException ex) {
                this.onFailure(ex);
                return false;
            }

            switch (unwrapResult.getStatus()) {
                case OK:
                    if (serverUnwrap.position() > 0) {
                        serverUnwrap.flip();
                        this.onInput(serverUnwrap);
                        serverUnwrap.compact();
                    }
                    break;

                case CLOSED:
                    this.onClosed();
                    return false;

                case BUFFER_OVERFLOW:
                    throw new IllegalStateException("failed to unwrap");

                case BUFFER_UNDERFLOW:
                    return false;
            }

            if (unwrapResult.getHandshakeStatus() == HandshakeStatus.FINISHED) {
                this.onSuccess();
                return false;
            }

            return true;
        }
    }

    public abstract class NioSSLProvider extends SSLProvider {
        private final ByteBuffer buffer = ByteBuffer.allocate(32 * 1024);
        private final SelectionKey key;

        public NioSSLProvider(SelectionKey key, SSLEngine engine, int bufferSize, Executor ioWorker,
                Executor taskWorkers) {
            super(engine, bufferSize, ioWorker, taskWorkers);
            this.key = key;
        }

        @Override
        public void onOutput(ByteBuffer encrypted) {
            try {
                ((WritableByteChannel) this.key.channel()).write(encrypted);
            } catch (IOException exc) {
                throw new IllegalStateException(exc);
            }
        }

        public boolean processInput() {
            buffer.clear();
            int bytes;
            try {
                bytes = ((ReadableByteChannel) this.key.channel()).read(buffer);
            } catch (IOException ex) {
                bytes = -1;
            }
            if (bytes == -1) {
                return false;
            }
            buffer.flip();
            ByteBuffer copy = ByteBuffer.allocate(bytes);
            copy.put(buffer);
            copy.flip();
            this.notify(copy);
            return true;
        }
    }

    @Test
    public void test() throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, UnrecoverableKeyException, URISyntaxException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

        // load CA
        X509Certificate cert = Helper.loadCertificate("WoTrus-SM2.crt");
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setCertificateEntry("alias", cert);

        // init trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);

        sc.init(null, tmf.getTrustManagers(), null);

        SSLSocketFactory ssf = sc.getSocketFactory();

        URI serverUrl = new URI("https://sm2only.ovssl.cn/");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.toURL().openConnection();
        conn.setRequestMethod("GET");
        conn.setSSLSocketFactory(ssf);
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", conn.getCipherSuite());
        // 读取服务器端返回的内容
        InputStream connInputStream = conn.getInputStream();
        InputStreamReader isReader = new InputStreamReader(connInputStream, "utf-8");
        BufferedReader br = new BufferedReader(isReader);
        StringBuffer buffer = new StringBuffer();
        String line = null;
        while ((line = br.readLine()) != null) {
            buffer.append(line);
        }
        Assert.assertTrue(buffer.toString().contains("沃通"));
        connInputStream.close();
    }

    @Test
    public void testEngine() throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException,
            CertificateException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);

        // 信任管理器
        BouncyCastleProvider bc = new BouncyCastleProvider();
        KeyStore ks = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("WoTrus-SM2.crt");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        ks.load(null, null);
        ks.setCertificateEntry("alias", cert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);

        sc.init(null, tmf.getTrustManagers(), null);

        SSLEngine engine = sc.createSSLEngine();
        engine.setUseClientMode(true);

        InetSocketAddress address = new InetSocketAddress("sm2only.ovssl.cn", 443);
        SocketChannel channel = SocketChannel.open();
        channel.configureBlocking(false);
        channel.connect(address);

        engine.beginHandshake();

        Selector selector = Selector.open();

        int ops = SelectionKey.OP_CONNECT | SelectionKey.OP_READ;

        SelectionKey key = channel.register(selector, ops);

        // create the worker threads
        final Executor ioWorker = Executors.newSingleThreadExecutor();
        final Executor taskWorkers = Executors.newFixedThreadPool(2);

        final int ioBufferSize = 32 * 1024;
        final NioSSLProvider ssl = new NioSSLProvider(key, engine, ioBufferSize, ioWorker, taskWorkers) {
            @Override
            public void onFailure(Exception ex) {
                System.out.println("handshake failure");
                ex.printStackTrace();
            }

            @Override
            public void onSuccess() {
                System.out.println("handshake success");
                SSLSession session = engine.getSession();
                try {
                    System.out.println("local principal: " + session.getLocalPrincipal());
                    System.out.println("remote principal: " + session.getPeerPrincipal());
                    System.out.println("cipher: " + session.getCipherSuite());
                } catch (Exception exc) {
                    exc.printStackTrace();
                }

                // HTTP request
                StringBuilder http = new StringBuilder();
                http.append("GET / HTTP/1.0\r\n");
                http.append("Connection: close\r\n");
                http.append("\r\n");
                byte[] data = http.toString().getBytes();
                ByteBuffer send = ByteBuffer.wrap(data);
                this.sendAsync(send);
            }

            @Override
            public void onInput(ByteBuffer decrypted) {
                // HTTP response
                byte[] dst = new byte[decrypted.remaining()];
                decrypted.get(dst);
                String response = new String(dst);
                System.out.print(response);
                System.out.flush();
            }

            @Override
            public void onClosed() {
                System.out.println("ssl session closed");
            }
        };

        // NIO selector
        while (true) {
            key.selector().select();
            Iterator<SelectionKey> keys = key.selector().selectedKeys().iterator();
            while (keys.hasNext()) {
                keys.next();
                keys.remove();
                ssl.processInput();
            }
        }
    }

    @Test
    public void testEngine2() throws Exception {
        // GMProvider provider = new GMProvider();
        // SSLContext sc = SSLContext.getInstance("TLS", provider);

        // X509Certificate cert = Helper.loadCertificate("WoTrus-SM2.crt");
        // KeyStore ks = KeyStore.getInstance("JKS");
        // ks.load(null, null);
        // ks.setCertificateEntry("alias", cert);

        // TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        // tmf.init(ks);

        // sc.init(null, tmf.getTrustManagers(), null);

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, null, null);
        SSLEngine engine = sc.createSSLEngine("sm2only.ovssl.cn", 443);
        engine.setUseClientMode(true);
        SSLSession session = engine.getSession();
        int appBufferMax = session.getApplicationBufferSize();
        int netBufferMax = session.getPacketBufferSize();
        ByteBuffer clientIn = ByteBuffer.allocate(appBufferMax + 50);
        ByteBuffer c2s = ByteBuffer.allocateDirect(netBufferMax);
        SSLEngineResult clientResult;
        while (!(engine.isOutboundDone() && engine.isInboundDone())) {
            clientResult = engine.wrap(ByteBuffer.wrap("Hi Server, I'm Client".getBytes()), c2s);
            if (clientResult.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
                Runnable runnable;
                while ((runnable = engine.getDelegatedTask()) != null) {
                    runnable.run();
                }
                HandshakeStatus hsStatus = engine.getHandshakeStatus();
                if (hsStatus == HandshakeStatus.NEED_TASK) {
                    throw new Exception("handshake shouldn't need additional tasks");
                }
            }
            c2s.flip();
            // clientResult = engine.unwrap(s2c, clientIn);
            c2s.compact();
        }
    }
}
