English | [简体中文](./README-CN.md)

<h1 align="center">GM JSSE</h1>

<p align="center">
<a href="https://search.maven.org/search?q=g:%22com.aliyun%22%20AND%20a:%22gmsse%22"><img src="https://img.shields.io/maven-central/v/com.aliyun/gmsse.svg?label=Maven%20Central" alt="Latest Stable Version"/></a>
<a href="https://travis-ci.org/aliyun/gm-jsse"><img src="https://travis-ci.org/aliyun/gm-jsse.svg?branch=master"/></a>
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

## Issues
[Opening an Issue](https://github.com/aliyun/gm-jsse/issues/new), Issues not conforming to the guidelines may be closed immediately.

## Changelog
Detailed changes for each release are documented in the [release notes](./ChangeLog.txt).

## License
[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.
