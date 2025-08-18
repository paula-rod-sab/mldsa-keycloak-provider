package com.paula.keycloak.crypto.keys;

import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class MLDSAPublicKey implements PublicKey {

    private static final ASN1ObjectIdentifier MLDSA_OID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17");

    private final byte[] publicKeyBytes;

    public MLDSAPublicKey(byte[] publicKeyBytes) {
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("Public key bytes cannot be null");
        }
        this.publicKeyBytes = publicKeyBytes;
    }

    @Override
    public String getAlgorithm() {
        return "MLDSA44";
    }

    @Override
    public byte[] getEncoded() {
        try {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(MLDSA_OID);
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, publicKeyBytes);
            return spki.getEncoded("DER");
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode MLDSA public key", e);
        }
    }

    @Override
    public String getFormat() {
        return "X.509";
    }
    
    public byte[] getRaw() {
        return publicKeyBytes;
    }
}
