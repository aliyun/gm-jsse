package com.aliyun.gmsse;

import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.handshake.*;
import com.aliyun.gmsse.record.Handshake;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

public class GMSSLSocketTest {

    public GMSSLContextSpi getSSLContext() throws NoSuchAlgorithmException, KeyManagementException {
        return new GMSSLContextSpi();
    }

    @Test
    public void getEnabledCipherSuitesTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        String[] strings = sslSocket.getEnabledCipherSuites();
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", strings[0]);
        sslSocket.close();
    }

    @Test
    @Ignore
    public void startHandshakeTest() throws Exception {
        GMSSLContextSpi context = getSSLContext();
        GMSSLSocket sslSocket = Mockito.spy(new GMSSLSocket(context, "www.aliyun.com", 80));
        InputStream inputStream = new ByteArrayInputStream(new byte[] { 22, 22 });
        Mockito.when(sslSocket.getInputStream()).thenReturn(inputStream);
        sslSocket.addHandshakeCompletedListener(null);
        sslSocket.removeHandshakeCompletedListener(null);
        try {
            sslSocket.startHandshake();
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("unexpected end of stream", e.getMessage());
        }
    }

    @Test
    public void getTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);

        sslSocket.setEnableSessionCreation(false);
        Assert.assertFalse(sslSocket.getEnableSessionCreation());

        String[] strings = sslSocket.getEnabledProtocols();
        Assert.assertEquals("NTLSv1.1", strings[0]);

        sslSocket.setNeedClientAuth(false);
        sslSocket.setWantClientAuth(false);
        Assert.assertFalse(sslSocket.getNeedClientAuth());

        Assert.assertNotNull(sslSocket.getSession());

        strings = sslSocket.getSupportedCipherSuites();
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", strings[0]);

        strings = sslSocket.getSupportedProtocols();
        Assert.assertEquals("NTLSv1.1", strings[0]);

        sslSocket.setUseClientMode(true);
        Assert.assertTrue(sslSocket.getUseClientMode());

        Assert.assertFalse(sslSocket.getWantClientAuth());
        sslSocket.close();
    }

    @Test
    public void setEnabledProtocolsTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        try {
            sslSocket.setEnabledProtocols(null);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertNotNull(e);
        }

        String[] strings = new String[0];
        try {
            sslSocket.setEnabledProtocols(strings);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertNotNull(e);
        }

        strings = new String[] { "NTLSv1.1", "test" };
        try {
            sslSocket.setEnabledProtocols(strings);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertEquals("unsupported protocol: test", e.getMessage());
        }

        // strings = new String[] { "NTLSv1.1", "NTLSv1.1" };
        // sslSocket.setEnabledProtocols(strings);
        // GMSSLSession gmsslSession = (GMSSLSession)sslSocket.getSession();
        // Assert.assertEquals(gmsslSession.enabledProtocols.get(0), ProtocolVersion.NTLS_1_1);
        sslSocket.close();
    }

    @Test
    public void setEnabledCipherSuitesTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);

        try {
            sslSocket.setEnabledCipherSuites(null);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertNotNull(e);
        }

        String[] strings = new String[0];
        try {
            sslSocket.setEnabledCipherSuites(strings);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertNotNull(e);
        }

        strings = new String[] { "ECC-SM2-WITH-SM4-SM3", "test" };
        try {
            sslSocket.setEnabledCipherSuites(strings);
            Assert.fail();
        } catch (IllegalArgumentException e) {
            Assert.assertEquals("unsupported suite: test", e.getMessage());
        }

        strings = new String[] { "ECC-SM2-WITH-SM4-SM3", "ECC-SM2-WITH-SM4-SM3" };
        sslSocket.setEnabledCipherSuites(strings);
        Field connection = sslSocket.getClass().getDeclaredField("connection");
        connection.setAccessible(true);
        connection.get(sslSocket);
        ConnectionContext cc = (ConnectionContext) connection.get(sslSocket);
        Assert.assertEquals(CipherSuite.NTLS_SM2_WITH_SM4_SM3, cc.sslConfig.enabledCipherSuites.get(0));
        sslSocket.close();
    }

    @Test
    @Ignore
    public void receiveServerHelloTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        Method receiveServerHello = GMSSLSocket.class.getDeclaredMethod("receiveServerHello");
        receiveServerHello.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{1});
        Mockito.when(recordStream.read()).thenReturn(record);

        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);
        try {
            receiveServerHello.invoke(gmsslSocket);
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("unexpected_message", e.getCause().getMessage());
        }

        record = new Record(Record.ContentType.HANDSHAKE, ProtocolVersion.NTLS_1_1, new byte[]{0x02});
        Mockito.when(recordStream.read()).thenReturn(record);
        recordStreamField.set(gmsslSocket, recordStream);
        receiveServerHello.invoke(gmsslSocket);

        Field securityParametersField = GMSSLSocket.class.getDeclaredField("securityParameters");
        securityParametersField.setAccessible(true);
        SecurityParameters securityParameters = (SecurityParameters) securityParametersField.get(gmsslSocket);
        byte[] resultBytes = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        Assert.assertTrue(Arrays.equals(resultBytes, securityParameters.serverRandom));
    }

    @Test
    @Ignore
    public void receiveServerCertificateTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        Method receiveServerCertificate = GMSSLSocket.class.getDeclaredMethod("receiveServerCertificate");
        receiveServerCertificate.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{0x0b});
        Mockito.when(recordStream.read()).thenReturn(record);

        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        GMSSLSession session = Mockito.mock(GMSSLSession.class);
        record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{0x0b});
        Mockito.when(recordStream.read()).thenReturn(record);
        session.cipherSuite = CipherSuite.NTLS_SM2_WITH_SM4_SM3;
        X509Certificate[] certs = new X509Certificate[]{};
        session.trustManager = new GMX509TrustManager(certs);

        PowerMockito.mockStatic(Certificate.class);
        Certificate certificate = Mockito.mock(Certificate.class);
        PowerMockito.when(Certificate.read(Mockito.any(InputStream.class))).thenReturn(certificate);

        record = new Record(Record.ContentType.HANDSHAKE, ProtocolVersion.NTLS_1_1, new byte[]{0x02});
        Mockito.when(recordStream.read()).thenReturn(record);
        recordStreamField.set(gmsslSocket, recordStream);
        receiveServerCertificate.invoke(gmsslSocket);
        Field handshakes = gmsslSocket.getClass().getDeclaredField("handshakes");
        handshakes.setAccessible(true);
        List<Handshake> list = (List<Handshake>) handshakes.get(gmsslSocket);
        Assert.assertEquals(1, list.size());
    }

    @Test
    @Ignore
    public void receiveServerKeyExchangeTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        Method receiveServerKeyExchange = GMSSLSocket.class.getDeclaredMethod("receiveServerKeyExchange");
        receiveServerKeyExchange.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{0x0c});
        Mockito.when(recordStream.read()).thenReturn(record);

        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);
        PowerMockito.mockStatic(Handshake.class);
        ServerKeyExchange serverKeyExchange = Mockito.mock(ServerKeyExchange.class);
        Mockito.when(serverKeyExchange.verify(Mockito.any(PublicKey.class), Mockito.any(byte[].class),
                Mockito.any(byte[].class), Mockito.any(X509Certificate.class))).thenReturn(true);
        Handshake skef = new Handshake(null, serverKeyExchange);
        PowerMockito.when(Handshake.read(Mockito.any(InputStream.class))).thenReturn(skef);
        X509Certificate first = Mockito.mock(X509Certificate.class);
        PowerMockito.when(first.getPublicKey()).thenReturn(Mockito.mock(PublicKey.class));
        X509Certificate two = Mockito.mock(X509Certificate.class);
        GMSSLSession gmsslSession = new GMSSLSession(null, null);
        gmsslSession.peerCerts = new X509Certificate[2];
        gmsslSession.peerCerts[0] = first;
        gmsslSession.peerCerts[1] = two;
        Field session = gmsslSocket.getClass().getDeclaredField("session");
        session.setAccessible(true);
        session.set(gmsslSocket, gmsslSession);

        byte[] bytes = new byte[]{1};
        SecurityParameters securityParameters = new SecurityParameters();
        securityParameters.serverRandom = bytes;
        securityParameters.clientRandom = bytes;
        Field securityParametersField = GMSSLSocket.class.getDeclaredField("securityParameters");
        securityParametersField.setAccessible(true);
        securityParametersField.set(gmsslSocket, securityParameters);

        receiveServerKeyExchange.invoke(gmsslSocket);
        Field handshakes = gmsslSocket.getClass().getDeclaredField("handshakes");
        handshakes.setAccessible(true);
        List<Handshake> list = (List<Handshake>) handshakes.get(gmsslSocket);
        Assert.assertEquals(1, list.size());

        serverKeyExchange = Mockito.mock(ServerKeyExchange.class);
        Mockito.when(serverKeyExchange.verify(Mockito.any(PublicKey.class), Mockito.any(byte[].class),
                Mockito.any(byte[].class), Mockito.any(X509Certificate.class))).thenThrow(new InvalidKeyException("test"));
        skef = new Handshake(null, serverKeyExchange);
        PowerMockito.when(Handshake.read(Mockito.any(InputStream.class))).thenReturn(skef);

        try {
            receiveServerKeyExchange.invoke(gmsslSocket);
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("server key exchange verify fails!", e.getCause().getMessage());
        }

        serverKeyExchange = Mockito.mock(ServerKeyExchange.class);
        Mockito.when(serverKeyExchange.verify(Mockito.any(PublicKey.class), Mockito.any(byte[].class),
                Mockito.any(byte[].class), Mockito.any(X509Certificate.class))).thenReturn(false);
        skef = new Handshake(null, serverKeyExchange);
        PowerMockito.when(Handshake.read(Mockito.any(InputStream.class))).thenReturn(skef);

        try {
            receiveServerKeyExchange.invoke(gmsslSocket);
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("server key exchange verify fails!", e.getCause().getMessage());
        }
    }

    @Test
    @Ignore
    public void receiveFinishedTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        Method receiveFinished = GMSSLSocket.class.getDeclaredMethod("receiveFinished");
        receiveFinished.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{1});
        Mockito.when(recordStream.read(true)).thenReturn(record);
        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        Finished finished = Mockito.mock(Finished.class);
        Mockito.when(finished.getBytes()).thenReturn(new byte[]{1});
        Handshake handshake = new Handshake(null, finished);
        PowerMockito.when(Handshake.read(Mockito.any(InputStream.class))).thenReturn(handshake);

        byte[] keyBlock = new byte[2];
        PowerMockito.mockStatic(Crypto.class);
        PowerMockito.when(Crypto.prf(Mockito.any(byte[].class), Mockito.any(byte[].class), Mockito.any(byte[].class),
                Mockito.any(int.class))).thenReturn(keyBlock);

        try {
            receiveFinished.invoke(gmsslSocket);
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("handshake_failure", e.getCause().getMessage());
        }
    }

    @Test
    @Ignore
    public void sendFinishedTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        Method sendFinished = GMSSLSocket.class.getDeclaredMethod("sendFinished");
        sendFinished.setAccessible(true);

        SecurityParameters securityParameters = new SecurityParameters();
        securityParameters.masterSecret = new byte[]{1};
        Field securityParametersField = GMSSLSocket.class.getDeclaredField("securityParameters");
        securityParametersField.setAccessible(true);
        securityParametersField.set(gmsslSocket, securityParameters);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Mockito.doNothing().when(recordStream).write(Mockito.any(Record.class), Mockito.any(boolean.class));
        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        sendFinished.invoke(gmsslSocket);
        Field handshakes = gmsslSocket.getClass().getDeclaredField("handshakes");
        handshakes.setAccessible(true);
        List<Handshake> list = (List<Handshake>) handshakes.get(gmsslSocket);
        Assert.assertEquals(1, list.size());
        Assert.assertTrue(list.get(0).body instanceof Finished);
    }

    @Test
    @Ignore
    public void receiveServerHelloDoneTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{0x02});
        Mockito.when(recordStream.read()).thenReturn(record);
        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        ConnectionContext conn = Mockito.mock(ConnectionContext.class);
        Field connectionField = GMSSLSocket.class.getDeclaredField("connection");
        connectionField.setAccessible(true);
        connectionField.set(gmsslSocket, conn);

        Method receiveServerHelloDone = ConnectionContext.class.getDeclaredMethod("receiveServerHelloDone");
        receiveServerHelloDone.setAccessible(true);
        receiveServerHelloDone.invoke(conn);
        Field handshakes = gmsslSocket.getClass().getDeclaredField("handshakes");
        handshakes.setAccessible(true);
        List<Handshake> list = (List<Handshake>) handshakes.get(gmsslSocket);
        Assert.assertTrue(list.get(0).body instanceof ServerHello);
    }

    @Test
    @Ignore
    public void sendChangeCipherSpecTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        Method sendChangeCipherSpec = GMSSLSocket.class.getDeclaredMethod("sendChangeCipherSpec");
        sendChangeCipherSpec.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Mockito.doNothing().when(recordStream).write(Mockito.any(Record.class));
        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        sendChangeCipherSpec.invoke(gmsslSocket);
        Mockito.verify(recordStream, Mockito.times(1)).write(Mockito.any(Record.class));
    }

    @Test
    @Ignore
    public void receiveChangeCipherSpecTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        Method receiveChangeCipherSpec = GMSSLSocket.class.getDeclaredMethod("receiveChangeCipherSpec");
        receiveChangeCipherSpec.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{0x02});
        Mockito.when(recordStream.read()).thenReturn(record);
        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        receiveChangeCipherSpec.invoke(gmsslSocket);
        Mockito.verify(recordStream, Mockito.times(1)).read();
    }

    @Test
    public void getOutputStreamTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket(getSSLContext(), "www.aliyun.com", 80);
        Assert.assertNotNull(gmsslSocket.getOutputStream());
        gmsslSocket.close();
    }
}
