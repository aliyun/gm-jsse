package com.aliyun;

import java.security.cert.X509Certificate;

enum ConnectionEnd {
    server,
    client
}

public class SecurityParameters {
    ConnectionEnd entity;
    // BulkCipherAlgorithm bulk_cipher_algorithm;
    // CipherType cipher_type;
    byte recordIVLength;
	public byte[] clientRandom;
	public byte[] serverRandom;
	public X509Certificate encryptionCert;
	public byte[] masterSecret;
}