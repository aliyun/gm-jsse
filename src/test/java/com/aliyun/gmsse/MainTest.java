package com.aliyun.gmsse;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.Test;

public class MainTest {
    @Test
    public void test() throws IOException, NoSuchAlgorithmException, KeyManagementException {
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);
        sc.init(null, null, null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        URL serverUrl = new URL("https://sm2test.ovssl.cn/");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", conn.getCipherSuite());
    }
}
