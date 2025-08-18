package com.paula.keycloak.crypto.keys;

import java.security.PrivateKey;
import java.util.Arrays;

/**
 * Implementation of a private key for the ML-DSA-44 post-quantum signature scheme.
 */
public class MLDSAPrivateKey implements PrivateKey {
    
    private final byte[] key;

    public MLDSAPrivateKey(byte[] key) {
        this.key = key;
    }

    @Override
    public String getAlgorithm() {
        return "MLDSA44";
    }

    @Override
    public byte[] getEncoded() {
        return Arrays.copyOf(key, key.length);
    }

    @Override
    public String getFormat() {
        return "RAW";
    }
    
}
