package com.aliyun.gmsse;

/**
 * Client authentication type.
 */
enum ClientAuthType {
    CLIENT_AUTH_NONE,           // turn off client authentication
    CLIENT_AUTH_REQUESTED,      // need to request client authentication
    CLIENT_AUTH_REQUIRED        // require client authentication
}