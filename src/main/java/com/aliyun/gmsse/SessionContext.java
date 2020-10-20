package com.aliyun.gmsse;

import java.util.Enumeration;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

public class SessionContext implements SSLSessionContext {

    public SessionContext() {

    }

    public Enumeration<byte[]> getIds() {
        // TODO Auto-generated method stub
        return null;
    }

    public SSLSession getSession(byte[] arg0) {
        // TODO Auto-generated method stub
        return null;
    }

    public int getSessionCacheSize() {
        // TODO Auto-generated method stub
        return 0;
    }

    public int getSessionTimeout() {
        // TODO Auto-generated method stub
        return 0;
    }

    public void setSessionCacheSize(int arg0) throws IllegalArgumentException {
        // TODO Auto-generated method stub

    }

    public void setSessionTimeout(int arg0) throws IllegalArgumentException {
        // TODO Auto-generated method stub

    }
    
}