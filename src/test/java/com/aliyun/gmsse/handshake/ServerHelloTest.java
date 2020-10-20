package com.aliyun.gmsse.handshake;

import com.aliyun.gmsse.CipherSuite;
import com.aliyun.gmsse.CompressionMethod;
import com.aliyun.gmsse.ProtocolVersion;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class ServerHelloTest {

    @Test
    public void toStringTest() {
        byte[] bytes = new byte[]{10};
        CompressionMethod compression = Mockito.mock(CompressionMethod.class);
        Mockito.when(compression.toString()).thenReturn("compression");
        ServerHello serverHello = new ServerHello(ProtocolVersion.NTLS_1_1, bytes, bytes,
                CipherSuite.NTLS_SM2_WITH_SM4_SM3, compression);
        String str = serverHello.toString();
        Assert.assertTrue(str.contains("version = NTLSv1.1;"));
        Assert.assertTrue(str.contains("random = 0a"));
        Assert.assertTrue(str.contains("sessionId = 0a"));
        Assert.assertTrue(str.contains("cipherSuite = ECC-SM2-WITH-SM4-SM3;"));
        Assert.assertTrue(str.contains("compressionMethod = compression;"));
    }

    @Test
    public void getTest() throws Exception{
        byte[] bytes = new byte[]{10};
        CompressionMethod compression = Mockito.mock(CompressionMethod.class);
        ServerHello serverHello = new ServerHello(ProtocolVersion.NTLS_1_1, bytes, bytes,
                CipherSuite.NTLS_SM2_WITH_SM4_SM3, compression);
        Assert.assertEquals(compression, serverHello.getCompressionMethod());
        Assert.assertNotNull(serverHello.getBytes());
        Assert.assertEquals(10, serverHello.getSessionId()[0]);
        Assert.assertEquals(bytes, serverHello.getRandom());
        Assert.assertEquals(CipherSuite.NTLS_SM2_WITH_SM4_SM3, serverHello.getCipherSuite());
    }
}
