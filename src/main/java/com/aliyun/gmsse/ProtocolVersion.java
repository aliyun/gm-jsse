package com.aliyun.gmsse;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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

    public String getName() {
        return name;
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

    public static String[] toStringArray(List<ProtocolVersion> protocolVersions) {
        if ((protocolVersions != null) && !protocolVersions.isEmpty()) {
            String[] protocolNames = new String[protocolVersions.size()];
            int i = 0;
            for (ProtocolVersion pv : protocolVersions) {
                protocolNames[i++] = pv.name;
            }

            return protocolNames;
        }

        return new String[0];
    }

    public static List<ProtocolVersion> namesOf(String[] protocolNames) {
        if (protocolNames == null || protocolNames.length == 0) {
            return Collections.<ProtocolVersion>emptyList();
        }

        List<ProtocolVersion> pvs = new ArrayList<>(protocolNames.length);
        for (String pn : protocolNames) {
            ProtocolVersion pv = ProtocolVersion.nameOf(pn);
            if (pv == null) {
                throw new IllegalArgumentException("unsupported protocol: " + pn);
            }

            pvs.add(pv);
        }

        return Collections.unmodifiableList(pvs);
    }

    static ProtocolVersion nameOf(String name) {
        List<ProtocolVersion> list = new ArrayList<>();
        list.add(NTLS_1_1);
        for (ProtocolVersion pv : list) {
            if (pv.name.equals(name)) {
                return pv;
            }
        }

        return null;
    }
}
