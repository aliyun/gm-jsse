[English](./README.md) | 简体中文

<p align="center">
<a href=" https://www.alibabacloud.com"><img src="https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg"></a>
</p>

<h1 align="center">Alibaba Cloud GM JSSE</h1>


<p align="center">
<a href="https://search.maven.org/search?q=g:%22com.aliyun%22%20AND%20a:%22gmsse%22"><img src="https://img.shields.io/maven-central/v/com.aliyun/gmsse.svg?label=Maven%20Central" alt="Latest Stable Version"/></a>
<a href="https://travis-ci.org/aliyun/gmsse"><img src="https://travis-ci.org/aliyun/gmsse.svg?branch=master"/></a>
<a href="https://codecov.io/gh/aliyun/gmsse"><img src="https://codecov.io/gh/aliyun/gmsse/branch/master/graph/badge.svg"/></a>
<a href="https://ci.appveyor.com/project/aliyun/gmsse"><img src="https://ci.appveyor.com/api/projects/status/levg38kb55k0pn1v/branch/master?svg=true"/></a>
</p>

## 环境要求

- The Alibaba Cloud Java SDK requires JDK 1.6 or later.

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

import com.aliyun.GMProvider;

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

## 问题
[Opening an Issue](https://github.com/aliyun/alibabacloud-gm-jsse/issues/new), Issues not conforming to the guidelines may be closed immediately.

## 发行说明
每个版本的详细更改记录在[发行说明](./ChangeLog.txt).

## 许可证
[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.
