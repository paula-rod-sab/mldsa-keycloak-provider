package com.paula.keycloak.crypto.signature;

import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureProviderFactory;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

public class MLDSASignatureProviderFactory implements SignatureProviderFactory {

    public static final String ID = "MLDSA44";
  
    @Override
    public SignatureProvider create(KeycloakSession session) {
        System.out.println("[MLDSASignatureProviderFactory] SignatureProvider created");
        KeyWrapper keyWrapper = getKeyWrapperFromSession(session);
        return new MLDSASignatureProvider(keyWrapper);
    }

    @Override
    public String getId() {
        return ID;
    }

    public SignatureVerifierContext verifier(KeyWrapper key) {
        System.out.printf("[MLDSASignatureProviderFactory] verifier() invoked for kid=%s%n", key.getKid());
        return new MLDSASignatureVerifierContext(key);
    }
   
    private KeyWrapper getKeyWrapperFromSession(KeycloakSession session) {
        KeyWrapper key = session.keys()
            .getKeysStream(session.getContext().getRealm(), KeyUse.SIG, "MLDSA44" )
            .findFirst()
            .orElseThrow(() -> new RuntimeException("ML-DSA key not found"));

        printKeyWrapper(key);

        return key;
    }

    public static void printKeyWrapper(KeyWrapper key) {
        if (key == null) {
            System.out.println("[MLDSASignatureProviderFactory] KeyWrapper is null");
            return;
        }

        System.out.printf("[MLDSASignatureProviderFactory] KeyWrapper info: kid=%s, algorithm=%s, type=%s, use=%s, status=%s%n",
            key.getKid(),
            key.getAlgorithm(),
            key.getType(),
            key.getUse(),
            key.getStatus());
    }

    public boolean supports(String algorithm) {
        return "MLDSA44".equals(algorithm);
    }
}
