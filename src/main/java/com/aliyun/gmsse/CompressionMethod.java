package com.aliyun.gmsse;

public class CompressionMethod {

    private final int value;

    public CompressionMethod(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString() {
        switch (value) {
            case 0:
                return "null";
            case 1:
                return "zlib";
            default:
                return "unknown(" + value + ")";
        }
    }

    public static final CompressionMethod NULL = new CompressionMethod(0);
    public static final CompressionMethod ZLIB = new CompressionMethod(1);

    public static CompressionMethod getInstance(int value) {
        switch (value) {
            case 0:
                return NULL;
            case 1:
                return ZLIB;
            default:
                return new CompressionMethod(value);
        }
    }
}
