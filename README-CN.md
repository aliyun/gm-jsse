[English](./README.md) | 简体中文

# 国密 JSSE

<p align="center">
<a href="https://search.maven.org/search?q=g:%22com.aliyun%22%20AND%20a:%22gmsse%22"><img src="https://img.shields.io/maven-central/v/com.aliyun/gmsse.svg?label=Maven%20Central" alt="Latest Stable Version"/></a>
<a href="https://github.com/aliyun/gm-jsse/actions/workflows/maven.yml"><img src="https://github.com/aliyun/gm-jsse/actions/workflows/maven.yml/badge.svg" alt="Java CI with Maven"/></a>
<a href="https://ci.appveyor.com/project/JacksonTian/alibabacloud-gm-jsse/branch/master"><img src="https://ci.appveyor.com/api/projects/status/7xwn4tw8gcl86im5/branch/master?svg=true"/></a>
<a href="https://codecov.io/gh/aliyun/gm-jsse"><img src="https://codecov.io/gh/aliyun/gm-jsse/branch/master/graph/badge.svg"/></a>
</p>

## 环境要求

- 需要 JDK 1.7 或以上.

## 安装依赖

```xml
<dependency>
    <groupId>com.aliyun</groupId>
    <artifactId>gmsse</artifactId>
    <version>{{使用maven标签所显示的版本}}</version>
</dependency>
```

## 快速使用

```java
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.net.URL;

import com.aliyun.gmsse.GMProvider;

public class Main {

    public static void main(String[] args) throws Exception {
        // 初始化 SSLSocketFactory
        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);
        sc.init(null, null, null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        URL serverUrl = new URL("https://xxx/");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // 设置 SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        System.out.println("used cipher suite:");
        System.out.println(conn.getCipherSuite());
    }
}
```

在新的版本中，GM-JSSE 增加了对服务端证书和 CA 证书的校验，如果 CA 根证书没有导入在系统中，可能会遇到校验错误。这时，你需要通过传递信任管理器的形式来传入 CA 证书。

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

### 双向认证

双向认证中，客户端需要传入双证书。

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

## 问题

[Opening an Issue](https://github.com/aliyun/gm-jsse/issues/new), Issues not conforming to the guidelines may be closed immediately.

## 发行说明

每个版本的详细更改记录在[发行说明](https://github.com/aliyun/gm-jsse/releases).

## 许可证

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.
