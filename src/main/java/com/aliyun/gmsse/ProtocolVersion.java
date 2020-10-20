package com.aliyun.gmsse;

import java.io.IOException;
import java.io.InputStream;

final public class ProtocolVersion implements Comparable {
    public static final ProtocolVersion NTLS_1_1 = new ProtocolVersion(1, 1, "NTLSv1.1");

    private final int major;
    private final int minor;
    private final String name;

    // Constructor.
    // -------------------------------------------------------------------------
    private ProtocolVersion(int major, int minor, String name) {
        this.major = major;
        this.minor = minor;
        this.name = name;
    }

    // Class methods.
    // -------------------------------------------------------------------------
    static ProtocolVersion read(InputStream in) throws IOException {
        int major = in.read() & 0xFF;
        int minor = in.read() & 0xFF;
        return getInstance(major, minor);
    }

    public static ProtocolVersion getInstance(int major, int minor) {
        if (major == 1) {
            switch (minor) {
                case 1:
                    return NTLS_1_1;
            }
        }
        return new ProtocolVersion(major, minor, "Unknow Protocol");
    }

    byte[] getEncoded() {
        return new byte[] { (byte) major, (byte) minor };
    }

    public int getMajor() {
        return major;
    }

    public int getMinor() {
        return minor;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || !(o instanceof ProtocolVersion)) {
            return false;
        }
        return ((ProtocolVersion) o).major == this.major && ((ProtocolVersion) o).minor == this.minor;
    }

    @Override
    public int hashCode() {
        return major << 8 | minor;
    }

    @Override
    public int compareTo(Object o) {
        if (o == null || !(o instanceof ProtocolVersion)) {
            return 1;
        }
        if (major > ((ProtocolVersion) o).major) {
            return 1;
        } else if (major < ((ProtocolVersion) o).major) {
            return -1;
        }
        if (minor > ((ProtocolVersion) o).minor) {
            return 1;
        } else if (minor < ((ProtocolVersion) o).minor) {
            return -1;
        }
        return 0;
    }

    @Override
    public String toString() {
        return name;
    }
}
