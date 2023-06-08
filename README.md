English | [简体中文](./README-CN.md)

# GM JSSE

<p align="center">
<a href="https://search.maven.org/search?q=g:%22com.aliyun%22%20AND%20a:%22gmsse%22"><img src="https://img.shields.io/maven-central/v/com.aliyun/gmsse.svg?label=Maven%20Central" alt="Latest Stable Version"/></a>
<a href="https://github.com/aliyun/gm-jsse/actions/workflows/maven.yml"><img src="https://github.com/aliyun/gm-jsse/actions/workflows/maven.yml/badge.svg" alt="Java CI with Maven"/></a>
<a href="https://ci.appveyor.com/project/JacksonTian/alibabacloud-gm-jsse/branch/master"><img src="https://ci.appveyor.com/api/projects/status/7xwn4tw8gcl86im5/branch/master?svg=true"/></a>
<a href="https://codecov.io/gh/aliyun/gm-jsse"><img src="https://codecov.io/gh/aliyun/gm-jsse/branch/master/graph/badge.svg"/></a>
</p>

## Requirements

- JDK 1.7 or later.

## Installation

```xml
<dependency>
    <groupId>com.aliyun</groupId>
    <artifactId>gmsse</artifactId>
    <version>{{see the version on the badge}}</version>
</dependency>
```

## Usage

```java
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.net.URL;

import com.aliyun.gmsse.GMProvider;

public class Main {

    public static void main(String[] args) throws Exception {
        // init SSLSocketFactory
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);
        sc.init(null, null, null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        URL serverUrl = new URL("https://xxx/");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        System.out.println("used cipher suite:");
        System.out.println(conn.getCipherSuite());
    }
}
```

In the new version, GM-JSSE will verify server and CA certificates, if the CA root certificates are not imported in system, maybe have verfication errors. So you need add trust manager with CA certificates.

```java
    BouncyCastleProvider bc = new BouncyCastleProvider();
    KeyStore ks = KeyStore.getInstance("JKS");
    CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
    FileInputStream is = new FileInputStream("/path/to/ca_cert");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
    ks.load(null, null);
    ks.setCertificateEntry("gmca", cert);

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
    tmf.init(ks);

    sc.init(null, tmf.getTrustManagers(), null);
    SSLSocketFactory ssf = sc.getSocketFactory();
```

### Two-way Authentication

In two-way authentication, the client needs to pass in two certificates.

```java

    public static X509Certificate loadCertificate(String path) throws KeyStoreException, CertificateException, FileNotFoundException {
        BouncyCastleProvider bc = new BouncyCastleProvider();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        InputStream is = Server.class.getClassLoader().getResourceAsStream(path);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        return cert;
    }

    public static PrivateKey loadPrivateKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream is = Server.class.getClassLoader().getResourceAsStream(path);
        InputStreamReader inputStreamReader = new InputStreamReader(is);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        StringBuilder sb = new StringBuilder();
        String line = null;
            while ((line = bufferedReader.readLine()) != null){
            if (line.startsWith("-")){
                continue;
            }
            sb.append(line).append("\n");
        }
        String ecKey = sb.toString().replaceAll("\\r\\n|\\r|\\n", "");
        Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] keyByte = base64Decoder.decode(ecKey.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec eks2 = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PrivateKey privateKey = keyFactory.generatePrivate(eks2);
        return privateKey;
    }

    KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
    ks.load(null, null);

    // 传入签名证书
    ks.setKeyEntry("sign", loadPrivateKey("sm2/client_sign.key"), new char[0], new X509Certificate[] {
        loadCertificate("sm2/client_sign.crt")
    });
    // 传入加密证书
    ks.setKeyEntry("enc", Server.loadPrivateKey("sm2/client_enc.key"), new char[0], new X509Certificate[] {
        oadCertificate("sm2/client_enc.crt")
    });

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(ks, new char[0]);

    // 传入根证书
    ks.setCertificateEntry("gmca", loadCertificate("sm2/chain-ca.crt"));

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
    tmf.init(ks);

    sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    SSLSocketFactory ssf = sc.getSocketFactory();
```

## Issues

[Opening an Issue](https://github.com/aliyun/gm-jsse/issues/new), Issues not conforming to the guidelines may be closed immediately.

## Changelog

Detailed changes for each release are documented in the [release notes](./ChangeLog.txt).

## License

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.
