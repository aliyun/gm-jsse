package com.aliyun;

import com.aliyun.crypto.Crypto;
import com.aliyun.handshake.*;
import com.aliyun.record.AppDataOutputStream;
import com.aliyun.record.Handshake;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@RunWith(PowerMockRunner.class)
@PrepareForTest({Certificate.class, Handshake.class, ClientKeyExchange.class, Record.class, Crypto.class})
public class GMSSLSocketTest {
    @Test
    public void getEnabledCipherSuitesTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket("www.aliyun.com", 80);
        String[] strings = sslSocket.getEnabledCipherSuites();
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", strings[0]);
        sslSocket.close();
    }

    @Test
    public void startHandshakeTest() throws Exception {
        GMSSLSocket sslSocket = Mockito.spy(new GMSSLSocket("www.aliyun.com", 80));
        InputStream inputStream = new ByteArrayInputStream(new byte[] { 22, 22 });
        Mockito.when(sslSocket.getInputStream()).thenReturn(inputStream);
        List<CipherSuite> enabledSuites = new ArrayList<CipherSuite>();
        enabledSuites.add(CipherSuite.NTLS_SM2_WITH_SM4_SM3);
        List<ProtocolVersion> enabledProtocols = new ArrayList<ProtocolVersion>();
        enabledProtocols.add(ProtocolVersion.NTLS_1_1);
        GMSSLSession mySSLSession = new GMSSLSession(enabledSuites, enabledProtocols);
        mySSLSession.random = new SecureRandom();
        Field session = GMSSLSocket.class.getDeclaredField("session");
        session.setAccessible(true);
        session.set(sslSocket, mySSLSession);
        sslSocket.addHandshakeCompletedListener(null);
        sslSocket.removeHandshakeCompletedListener(null);
        try {
            sslSocket.startHandshake();
            Assert.fail();
        } catch (Exception e) {
            Assert.assertNotNull("unexpected end of stream", e.getMessage());
        }
    }

    @Test
    public void getTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket("www.aliyun.com", 80);

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
        GMSSLSocket sslSocket = new GMSSLSocket("www.aliyun.com", 80);
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

        strings = new String[] { "NTLSv1.1", "NTLSv1.1" };
        sslSocket.setEnabledProtocols(strings);
        Assert.assertEquals(sslSocket.session.enabledProtocols.get(0), ProtocolVersion.NTLS_1_1);
        sslSocket.close();
    }

    @Test
    public void setEnabledCipherSuitesTest() throws Exception {
        GMSSLSocket sslSocket = new GMSSLSocket("www.aliyun.com", 80);

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
        Assert.assertEquals(CipherSuite.NTLS_SM2_WITH_SM4_SM3, sslSocket.session.enabledSuites.get(0));
        sslSocket.close();
    }

    @Test
    public void receiveServerHelloTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
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
    public void receiveServerCertificateTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
        Method receiveServerCertificate = GMSSLSocket.class.getDeclaredMethod("receiveServerCertificate");
        receiveServerCertificate.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{0x0b});
        Mockito.when(recordStream.read()).thenReturn(record);

        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        PowerMockito.mockStatic(Certificate.class);
        Certificate certificate = Mockito.mock(Certificate.class);
        PowerMockito.when(Certificate.read(Mockito.any())).thenReturn(certificate);

        receiveServerCertificate.invoke(gmsslSocket);
        Assert.assertEquals(1, gmsslSocket.handshakes.size());
    }

    @Test
    public void receiveServerKeyExchangeTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
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
        PowerMockito.when(Handshake.read(Mockito.any())).thenReturn(skef);

        X509Certificate first = Mockito.mock(X509Certificate.class);
        Mockito.when(first.getPublicKey()).thenReturn(null);
        X509Certificate two = Mockito.mock(X509Certificate.class);
        GMSSLSession gmsslSession = new GMSSLSession(null, null);
        gmsslSession.peerCerts = new X509Certificate[2];
        gmsslSession.peerCerts[0] = first;
        gmsslSession.peerCerts[1] = two;
        gmsslSocket.session = gmsslSession;

        receiveServerKeyExchange.invoke(gmsslSocket);
        Assert.assertEquals(1, gmsslSocket.handshakes.size());

        serverKeyExchange = Mockito.mock(ServerKeyExchange.class);
        Mockito.when(serverKeyExchange.verify(Mockito.any(PublicKey.class), Mockito.any(byte[].class),
                Mockito.any(byte[].class), Mockito.any(X509Certificate.class))).thenThrow(new InvalidKeyException("test"));
        skef = new Handshake(null, serverKeyExchange);
        PowerMockito.when(Handshake.read(Mockito.any())).thenReturn(skef);

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
        PowerMockito.when(Handshake.read(Mockito.any())).thenReturn(skef);

        try {
            receiveServerKeyExchange.invoke(gmsslSocket);
            Assert.fail();
        } catch (Exception e) {
            Assert.assertEquals("server key exchange verify fails!", e.getCause().getMessage());
        }
    }

    @Test
    public void sendClientKeyExchangeTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
        Method sendClientKeyExchange = GMSSLSocket.class.getDeclaredMethod("sendClientKeyExchange");
        sendClientKeyExchange.setAccessible(true);

        byte[] bytes = new byte[]{1};
        GMSSLSession gmsslSession = new GMSSLSession(null, null);
        SecureRandom secureRandom = Mockito.mock(SecureRandom.class);
        Mockito.when(secureRandom.generateSeed(46)).thenReturn(bytes);
        gmsslSession.random = secureRandom;
        gmsslSocket.session = gmsslSession;

        byte[] keyBlock = new byte[200];
        PowerMockito.mockStatic(Crypto.class);
        PowerMockito.when(Crypto.prf(Mockito.any(byte[].class), Mockito.any(byte[].class), Mockito.any(byte[].class),
                Mockito.any(int.class))).thenReturn(keyBlock);
        PowerMockito.when(Crypto.encrypt(Mockito.any(BCECPublicKey.class), Mockito.any(byte[].class))).thenReturn(bytes);

        SecurityParameters securityParameters = new SecurityParameters();
        securityParameters.serverRandom = bytes;
        securityParameters.clientRandom = bytes;
        X509Certificate x509Certificate = Mockito.mock(X509Certificate.class);
        BCECPublicKey bcecPublicKey = Mockito.mock(BCECPublicKey.class);
        Mockito.when(x509Certificate.getPublicKey()).thenReturn(bcecPublicKey);
        securityParameters.encryptionCert = x509Certificate;
        Field securityParametersField = GMSSLSocket.class.getDeclaredField("securityParameters");
        securityParametersField.setAccessible(true);
        securityParametersField.set(gmsslSocket, securityParameters);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Mockito.doNothing().when(recordStream).write(Mockito.any(Record.class));
        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        sendClientKeyExchange.invoke(gmsslSocket);
        Mockito.verify(recordStream, Mockito.times(1)).setClientMacKey(Mockito.any());
        Mockito.verify(recordStream, Mockito.times(1)).setServerMacKey(Mockito.any());
        Mockito.verify(recordStream, Mockito.times(1)).setWriteCipher(Mockito.any());
        Mockito.verify(recordStream, Mockito.times(1)).setReadCipher(Mockito.any());
        Mockito.verify(recordStream, Mockito.times(1)).setClientWriteIV(Mockito.any());
        Mockito.verify(recordStream, Mockito.times(1)).setServerWriteIV(Mockito.any());
    }

    @Test
    public void receiveFinishedTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
        Method receiveFinished = GMSSLSocket.class.getDeclaredMethod("receiveFinished");
        receiveFinished.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{1});
        Mockito.when(recordStream.read(true)).thenReturn(record);
        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        PowerMockito.mockStatic(Handshake.class);
        Finished finished = Mockito.mock(Finished.class);
        Mockito.when(finished.getBytes()).thenReturn(new byte[]{1});
        Handshake handshake = new Handshake(null, finished);
        PowerMockito.when(Handshake.read(Mockito.any())).thenReturn(handshake);

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
    public void sendFinishedTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
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
        Assert.assertEquals(1, gmsslSocket.handshakes.size());
    }

    @Test
    public void receiveServerHelloDoneTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
        Method receiveServerHelloDone = GMSSLSocket.class.getDeclaredMethod("receiveServerHelloDone");
        receiveServerHelloDone.setAccessible(true);

        RecordStream recordStream = Mockito.mock(RecordStream.class);
        Record record = new Record(Record.ContentType.ALERT, ProtocolVersion.NTLS_1_1, new byte[]{0x02});
        Mockito.when(recordStream.read()).thenReturn(record);
        Field recordStreamField = GMSSLSocket.class.getDeclaredField("recordStream");
        recordStreamField.setAccessible(true);
        recordStreamField.set(gmsslSocket, recordStream);

        receiveServerHelloDone.invoke(gmsslSocket);
        Assert.assertTrue(gmsslSocket.handshakes.get(0).body instanceof ServerHello);
    }

    @Test
    public void sendChangeCipherSpecTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
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
    public void receiveChangeCipherSpecTest() throws Exception {
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
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
        GMSSLSocket gmsslSocket = new GMSSLSocket("www.aliyun.com", 80);
        Assert.assertTrue(gmsslSocket.getOutputStream() instanceof AppDataOutputStream);
        gmsslSocket.close();
    }
}
