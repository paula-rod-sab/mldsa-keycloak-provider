package com.paula.keycloak.crypto.signature;

import org.openquantumsafe.Signature;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;

public class MLDSASignatureSignerContext implements SignatureSignerContext {

    private final Signature signer;
    private final byte[] privateKey;
    private final String kid;
    private final String algorithm;

    public MLDSASignatureSignerContext(KeyWrapper key) throws RuntimeException {
        this.privateKey = key.getPrivateKey().getEncoded();
        this.kid = key.getKid();
        this.algorithm = key.getAlgorithm();
        try {
            signer = new Signature("ML-DSA-44", privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize ML-DSA signature", e);
        }
    }

    public String getKid() {
        return kid;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getHashAlgorithm() {
        return "SHA-256"; 
    }
  
    public byte[] sign(byte[] data) throws RuntimeException {
        System.out.printf("[MLDSASignatureSignerContext] Signing data with kid=%s%n", kid);
        try {
            byte[] signature = signer.sign(data);
            System.out.printf("[MLDSASignatureSignerContext] Data signed successfully, signature length: %d bytes%n", signature.length);
            System.out.println("[MLDSASignatureSignerContext] Signature (hex): " + bytesToHex(signature));
            return signature;
        } catch (Exception e) {
            throw new RuntimeException("Signing failed", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public void close() {
        signer.dispose_sig();
        System.out.printf("[MLDSASignatureSignerContext] Signer closed for kid=%s%n", kid);
    }
}
