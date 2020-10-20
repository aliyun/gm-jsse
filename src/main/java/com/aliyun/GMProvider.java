package com.aliyun;

import java.security.Provider;

public class GMProvider extends Provider {

    public GMProvider() {
        super(PROVIDER_NAME, 1.0, "Alibaba Cloud GM JSSE provider");
        put("SSLContext.TLS", GMSSLContextSpi.class.getName());
    }

    /**
     *
     */
    private static final long serialVersionUID = -8752236141095716196L;
    public static final String PROVIDER_NAME = "GMProvider";
}
