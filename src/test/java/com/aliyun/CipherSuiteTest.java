package com.aliyun;

import com.aliyun.gmsse.CipherSuite;
import com.aliyun.gmsse.ProtocolVersion;
import org.junit.Assert;
import org.junit.Test;

public class CipherSuiteTest {

    @Test
    public void getTest() {
        String str = CipherSuite.NTLS_SM2_WITH_SM4_SM3.getName();
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", str);

        str = CipherSuite.NTLS_SM2_WITH_SM4_SM3.getKeyExchange();
        Assert.assertEquals("SM2", str);

        str = CipherSuite.NTLS_SM2_WITH_SM4_SM3.getSignature();
        Assert.assertEquals("SM4", str);

        CipherSuite cipherSuite = CipherSuite.forName("name");
        Assert.assertNull(cipherSuite);
    }

    @Test
    public void resolveTest() {
        CipherSuite cipherSuite = CipherSuite.resolve(0xe0, 0x13, ProtocolVersion.NTLS_1_1);
        Assert.assertEquals(cipherSuite, CipherSuite.NTLS_SM2_WITH_SM4_SM3);

        cipherSuite = CipherSuite.resolve(0x00, 0x13, ProtocolVersion.NTLS_1_1);
        Assert.assertNull(cipherSuite);

        cipherSuite = CipherSuite.resolve(0xe0, 0xe3, ProtocolVersion.NTLS_1_1);
        Assert.assertNull(cipherSuite);
    }
}
