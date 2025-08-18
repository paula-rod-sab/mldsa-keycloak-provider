package com.paula.keycloak.crypto.keys;

import java.util.stream.Stream;

import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.KeyProvider;

/**
 * Key provider for MLDSA.
 */
public class MLDSAKeyProvider implements KeyProvider {

    private static final String KEY_TYPE = "PQC";
    private static final String ALGORITHM = "MLDSA44";
    private static final String KEY_ID = "ml-dsa-key";

    private final byte[] publicKey;
    private final byte[] privateKey;

    public MLDSAKeyProvider(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
        KeyWrapper key = new KeyWrapper();
        key.setType(KEY_TYPE);
        key.setAlgorithm(ALGORITHM);
        key.setUse(KeyUse.SIG);
        key.setKid(KEY_ID);
        key.setPublicKey(new MLDSAPublicKey(publicKey));
        key.setPrivateKey(new MLDSAPrivateKey(privateKey));
        key.setStatus(KeyStatus.ACTIVE);

        System.out.printf(
            "[MLDSAKeyProvider] Key generated with KID=%s, format=%s, encoded length=%d%n",
            KEY_ID,
            key.getPublicKey().getFormat(),
            key.getPublicKey().getEncoded().length
        );

        return Stream.of(key);
    }

    public KeyWrapper getKey(String kid) {
        return getKeysStream()
            .filter(k -> kid.equals(k.getKid()))
            .findFirst()
            .orElse(null);
    }

    @Override
    public void close() {}

}
