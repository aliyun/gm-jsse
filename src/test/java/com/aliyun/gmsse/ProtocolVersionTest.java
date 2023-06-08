package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ProtocolVersionTest {

    @Test
    public void compareToTest() throws Exception {
        Assert.assertEquals(1, ProtocolVersion.NTLS_1_1.compareTo(null));
        Assert.assertEquals(1, ProtocolVersion.NTLS_1_1.compareTo("null"));

        ProtocolVersion protocolVersion = ProtocolVersion.getInstance(2, 2);
        Assert.assertEquals(1, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));

        protocolVersion = ProtocolVersion.getInstance(0, 2);
        Assert.assertEquals(-1, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));

        protocolVersion = ProtocolVersion.getInstance(1, 2);
        Assert.assertEquals(1, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));

        protocolVersion = ProtocolVersion.getInstance(1, -1);
        Assert.assertEquals(-1, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));

        protocolVersion = ProtocolVersion.getInstance(1, 1);
        Assert.assertEquals(0, protocolVersion.compareTo(ProtocolVersion.NTLS_1_1));
    }

    @Test
    public void readTest() throws Exception {
        ProtocolVersion protocolVersion = ProtocolVersion.getInstance(1, 1);
        Method getEncoded = ProtocolVersion.class.getDeclaredMethod("getEncoded");
        getEncoded.setAccessible(true);
        byte[] bytes = (byte[]) getEncoded.invoke(protocolVersion);
        Assert.assertEquals(1, bytes[0]);
        Assert.assertEquals(1, bytes[1]);
    }

    @Test
    public void hashTest() {
        Assert.assertEquals(257, ProtocolVersion.NTLS_1_1.hashCode());
    }

    @Test
    public void equalsTest() {
        Assert.assertFalse(ProtocolVersion.NTLS_1_1.equals(null));
        Assert.assertFalse(ProtocolVersion.NTLS_1_1.equals("null"));
        Assert.assertTrue(ProtocolVersion.NTLS_1_1.equals(ProtocolVersion.NTLS_1_1));
        Assert.assertFalse(ProtocolVersion.NTLS_1_1.equals(ProtocolVersion.getInstance(1, 2)));
        Assert.assertFalse(ProtocolVersion.NTLS_1_1.equals(ProtocolVersion.getInstance(2, 2)));
    }

    @Test
    public void namesOfTest() {
        List<ProtocolVersion> pvs = ProtocolVersion.namesOf(null);
        Assert.assertTrue(pvs.size() == 0);
        Assert.assertTrue(ProtocolVersion.namesOf(new String[] {}).size() == 0);
    }

    @Test
    public void toStringArrayTest() {
        Assert.assertArrayEquals(new String[] {}, ProtocolVersion.toStringArray(null));
        Assert.assertArrayEquals(new String[] {}, ProtocolVersion.toStringArray(Collections.<ProtocolVersion>emptyList()));
        ProtocolVersion[] pvs = new ProtocolVersion[] {ProtocolVersion.NTLS_1_1};
        Assert.assertArrayEquals(new String[] {"NTLSv1.1"}, ProtocolVersion.toStringArray(Arrays.asList(pvs)));
    }
    
}
