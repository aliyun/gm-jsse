package com.aliyun.gmsse;

public class Record {
    ContentType contentType;
    ProtocolVersion version;
    public byte[] fragment;

    public Record(ContentType contentType, ProtocolVersion version, byte[] fragment) {
        this.contentType = contentType;
        this.version = version;
        this.fragment = fragment;
    }

    /**
     * ContentType
     */
    public static class ContentType {
        final public static ContentType CHANGE_CIPHER_SPEC = new ContentType(20, "change_cipher_spec");
        final public static ContentType ALERT = new ContentType(21, "alert");
        final public static ContentType HANDSHAKE = new ContentType(22, "handshake");
        final public static ContentType APPLICATION_DATA = new ContentType(23, "application_data");
        final public static ContentType SITE2SITE = new ContentType(80, "site2site");

        final private int value;
        final private String name;

        ContentType(int value, String name) {
            this.value = value;
            this.name = name;
        }

        public static ContentType getInstance(int value) {
            switch (value) {
                case 20:
                    return CHANGE_CIPHER_SPEC;
                case 21:
                    return ALERT;
                case 22:
                    return HANDSHAKE;
                case 23:
                    return APPLICATION_DATA;
                case 24:
                    return SITE2SITE;
            }
            return new ContentType(value, "unknow content type");
        }

        public String toString() {
            return "content type: " + name;
        }

        public int getValue() {
            return value;
        }
    }
}