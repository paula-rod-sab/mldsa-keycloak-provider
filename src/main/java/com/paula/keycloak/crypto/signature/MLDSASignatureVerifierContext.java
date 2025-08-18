package com.paula.keycloak.crypto.signature;

import org.openquantumsafe.Signature;

import java.io.IOException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;

public class MLDSASignatureVerifierContext implements SignatureVerifierContext {

    private final Signature verifier;
    private final byte[] publicKey;
    private final String kid;
    private final String algorithm;


    public MLDSASignatureVerifierContext(KeyWrapper key) throws RuntimeException {
        System.out.printf("[MLDSASignatureVerifierContext] Initializing verifier for kid=%s%n", key.getKid());
        try {
            this.kid = key.getKid();
            this.algorithm = key.getAlgorithm();
            this.publicKey = extractRawPublicKey(key);
            this.verifier = new Signature("ML-DSA-44");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize ML-DSA verifier or to decode the public key", e);
        }
    }
    
    private byte[] extractRawPublicKey(KeyWrapper publicKey) throws IOException {
        byte[] encoded = publicKey.getPublicKey().getEncoded();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(encoded);
        byte[] extracted = spki.getPublicKeyData().getBytes();

        System.out.printf("[MLDSASignatureVerifierContext] OID read: %s%n", spki.getAlgorithm().getAlgorithm());
        System.out.printf("[MLDSASignatureVerifierContext] Encoded key bytes length: %d%n", encoded.length);
        System.out.printf("[MLDSASignatureVerifierContext] Extracted public key bytes length: %d%n", extracted.length);

        return extracted;
    }

    public String getKid() {
        return kid;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public boolean verify(byte[] data, byte[] signature) {
        return verify(data, signature, publicKey);
    }

    public boolean verify(byte[] data, byte[] signature, byte[] publicKey) throws RuntimeException {
        System.out.printf("[MLDSASignatureVerifierContext] Verifying signature for kid=%s%n", kid);
        try {
            boolean result = verifier.verify(data, signature, publicKey);
            System.out.printf("[MLDSASignatureVerifierContext] Verification result: %b%n", result);
            System.out.printf("[MLDSASignatureVerifierContext] Signature (hex): %s%n", bytesToHex(signature));
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Error during verification", e);
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
        verifier.dispose_sig();
        System.out.printf("[MLDSASignatureVerifierContext] Verifier closed for kid=%s%n", kid);
    }
}
