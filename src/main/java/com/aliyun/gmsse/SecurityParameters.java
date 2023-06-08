package com.aliyun.gmsse;

import java.security.cert.X509Certificate;

public class SecurityParameters {
    // BulkCipherAlgorithm bulk_cipher_algorithm;
    // CipherType cipher_type;
    byte recordIVLength;
	public byte[] clientRandom;
	public byte[] serverRandom;
	public X509Certificate encryptionCert;
	public byte[] masterSecret;
}