package com.aliyun.gmsse;

import com.aliyun.gmsse.record.Alert;

import javax.net.ssl.SSLException;

public class AlertException extends SSLException {
    /**
     *
     */
    private static final long serialVersionUID = -2141851102337515375L;

    private Alert alert;
    private boolean isLocal;

    AlertException(Alert alert, boolean isLocal) {
        super(alert.getDescription().toString());
        this.alert = alert;
        this.isLocal = isLocal;
    }
}
