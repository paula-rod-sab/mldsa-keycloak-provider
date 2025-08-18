package com.paula.keycloak.crypto.signature;

import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;

public class MLDSASignatureProvider implements SignatureProvider {


    private static final String ALGORITHM = "MLDSA44";
    private static final String TYPE = "PQC";

    private final KeyWrapper key;

    public MLDSASignatureProvider(KeyWrapper key) {
        this.key = key;
    }

    @Override
    public SignatureSignerContext signer() throws SignatureException {
        SignatureProvider.checkKeyForSignature(key, ALGORITHM, TYPE);
        return new MLDSASignatureSignerContext(key);
    }

    @Override
    public SignatureSignerContext signer(KeyWrapper key) throws SignatureException {
        SignatureProvider.checkKeyForSignature(key, ALGORITHM, TYPE);
        return new MLDSASignatureSignerContext(key);
    }

    @Override
    public SignatureVerifierContext verifier(String kid) throws VerificationException {
        if (!key.getKid().equals(kid)) {
            throw new SignatureException("Key ID mismatch");
        }
        return verifier(key);
    }

    @Override
    public SignatureVerifierContext verifier(KeyWrapper key) throws VerificationException {
        System.out.println("[MLDSASignatureProvider] Verifier invoked");
        SignatureProvider.checkKeyForVerification(key, ALGORITHM, TYPE);
        return new MLDSASignatureVerifierContext(key);
    }

    @Override
    public boolean isAsymmetricAlgorithm() {
        return true;
    }

}
