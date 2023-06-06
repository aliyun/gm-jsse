package com.aliyun.gmsse;

import java.security.Provider;

public class GMProvider extends Provider {

    public GMProvider() {
        super(PROVIDER_NAME, 1.0, "Alibaba Cloud GM JSSE provider");
        put("SSLContext.TLS", GMSSLContextSpi.class.getName());
        put("KeyManagerFactory.X509",   GMX509KeyManagerFactory.class.getName());
        put("TrustManagerFactory.X509", GMX509TrustManagerFactory.class.getName());
    }

    private static final long serialVersionUID = -8752236141095716196L;
    private static final String PROVIDER_NAME = "GMProvider";
}
