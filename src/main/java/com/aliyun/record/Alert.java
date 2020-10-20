package com.aliyun.record;

import java.io.IOException;
import java.io.InputStream;

public class Alert implements RecordFragment {

    /** The alert level enumerated. */
    private final Level level;

    /** The alert description enumerated. */
    private final Description description;

    public Alert(Level level, Description description) {
        this.level = level;
        this.description = description;
    }

    public Description getDescription() {
        return description;
    }

    public static class Level {

        public final static Level WARNING = new Level(1, "warning");
        public final static Level FATAL = new Level(2, "fatal");
        private int value;
        private String name;

        public Level(int value, String name) {
            this.value = value;
            this.name = name;
        }

        public static Level getInstance(int value) {
            if (value == 1) {
                return WARNING;
            } else if (value == 2) {
                return FATAL;
            }
            return new Level(value, "unknow alert level");
        }
    }

    public static class Description {
        public final static Description CLOSE_NOTIFY = new Description(0, "close_notify");
        public final static Description UNEXPECTED_MESSAGE = new Description(10, "unexpected_message");
        public final static Description BAD_RECORD_MAC = new Description(20, "bad_record_mac");
        public final static Description DECRYPTION_FAILED = new Description(21, "decryption_failed");
        public final static Description RECORD_OVERFLOW = new Description(22, "record_overflow");
        public final static Description DECOMPRESION_FAILURE = new Description(30, "decompresion_failure");
        public final static Description HANDSHAKE_FAILURE = new Description(40, "handshake_failure");
        public final static Description BAD_CERTIFICATE = new Description(42, "bad_certificate");
        public final static Description UNSUPPORTED_CERTIFICATE = new Description(43, "unsupported_certificate");
        public final static Description CERTIFICATE_REVOKED = new Description(44, "certificate_revoked");
        public final static Description CERTIFICATE_EXPIRED = new Description(45, "certificate_expired");
        public final static Description CERTIFICATE_UNKNOWN = new Description(46, "certificate_unknown");
        public final static Description ILEGAL_PARAMETER = new Description(47, "illegal_parameter");
        public final static Description UNKNOWN_CA = new Description(48, "unknown_ca");
        public final static Description ACES_DENIED = new Description(49, "acces_denied");
        public final static Description DECODE_ERROR = new Description(50, "decode_error");
        public final static Description DECRYPT_ERROR = new Description(51, "decrypt_error");
        public final static Description PROTOCOL_VERSION = new Description(70, "protocol_version");
        public final static Description INSUFICIENT_SECURITY = new Description(71, "insuficient_security");
        public final static Description INTERNAL_ERROR = new Description(80, "internal_eror");
        public final static Description USER_CANCELED = new Description(90, "user_canceled");
        public final static Description UNSUPPORTED_SITE2SITE = new Description(200, "unsupported_site2site");
        public final static Description NO_AREA = new Description(201, "no_area");
        public final static Description UNSUPPORTED_AREATYPE = new Description(202, "unsupported_areatype");
        public final static Description BAD_IBCPARAM = new Description(203, "bad_ibcparam");
        public final static Description UNSUPPORTED_IBCPARAM = new Description(204, "unsupported_ibcparam");
        public final static Description IDENTITY_NEED = new Description(205, "identity_need");

        private int value;
        private String name;

        public Description(int value, String name) {
            this.value = value;
            this.name = name;
        }

        public static Description getInstance(int value) {
            switch (value) {
                case 0:
                    return CLOSE_NOTIFY;
                case 10:
                    return UNEXPECTED_MESSAGE;
                case 20:
                    return BAD_RECORD_MAC;
                case 21:
                    return DECRYPTION_FAILED;
                case 22:
                    return RECORD_OVERFLOW;
                case 30:
                    return DECOMPRESION_FAILURE;
                case 40:
                    return HANDSHAKE_FAILURE;
                case 42:
                    return BAD_CERTIFICATE;
                case 43:
                    return UNSUPPORTED_CERTIFICATE;
                case 44:
                    return CERTIFICATE_REVOKED;
                case 45:
                    return CERTIFICATE_EXPIRED;
                case 46:
                    return CERTIFICATE_UNKNOWN;
                case 47:
                    return ILEGAL_PARAMETER;
                case 48:
                    return UNKNOWN_CA;
                case 49:
                    return ACES_DENIED;
                case 50:
                    return DECODE_ERROR;
                case 51:
                    return DECRYPT_ERROR;
                case 70:
                    return PROTOCOL_VERSION;
                case 71:
                    return INSUFICIENT_SECURITY;
                case 80:
                    return INTERNAL_ERROR;
                case 90:
                    return USER_CANCELED;
                case 200:
                    return UNSUPPORTED_SITE2SITE;
                case 201:
                    return NO_AREA;
                case 202:
                    return UNSUPPORTED_AREATYPE;
                case 203:
                    return BAD_IBCPARAM;
                case 204:
                    return UNSUPPORTED_IBCPARAM;
                case 205:
                    return IDENTITY_NEED;
                default:
                    return new Description(value, "unknow description");
            }
        }

        @Override
        public String toString() {
            return name;
        }
    }

    @Override
    public byte[] getBytes() throws IOException {
        return new byte[] { (byte) level.value, (byte) description.value };
    }

    public static Alert read(InputStream input) throws IOException {
        Level level = Level.getInstance(input.read());
        Description desc = Description.getInstance(input.read());
        return new Alert(level, desc);
    }
}
