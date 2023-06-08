package com.aliyun.gmsse;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class Util {
    private static String HEX = "0123456789abcdef";

    public static String hexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        ByteArrayInputStream is = new ByteArrayInputStream(bytes);
        byte[] line = new byte[16];
        int length;
        while ((length = is.read(line, 0, line.length)) > 0) {
            for (int i = 0; i < length; i = i + 1) {
                sb.append(HEX.charAt(line[i] >>> 4 & 0x0F));
                sb.append(HEX.charAt(line[i] & 0x0F));

                if (i < length - 1) {
                    sb.append(" ");
                }

                if (i == 7) {
                    sb.append(" ");
                }
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    public static byte[] safeRead(InputStream input, int len) throws IOException {
        byte[] buf = new byte[len];
        int count = 0;
        while (count < len) {
            int l = input.read(buf, count, len - count);
            if (l == -1) {
                throw new EOFException("unexpected end of stream");
            }
            count += l;
        }
        return buf;
    }

    public static String getProperty(final String name) {
        return AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
                return System.getProperty(name);
            }
        });
    }
}
