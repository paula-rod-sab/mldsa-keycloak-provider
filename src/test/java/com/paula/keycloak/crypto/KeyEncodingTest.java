package com.paula.keycloak.crypto;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.openquantumsafe.Signature;


public class KeyEncodingTest {
    public static void main(String[] args) throws IOException {

        byte[] publicKeyBytes = loadKeyFromFile("public.key");

        ASN1ObjectIdentifier mlDsaOid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18");
        AlgorithmIdentifier algId = new AlgorithmIdentifier(mlDsaOid); 
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, publicKeyBytes);
        byte[] encoded = spki.getEncoded("DER");

        System.out.println("Original key length: " + publicKeyBytes.length);
        System.out.println("Encoded SPKI length: " + encoded.length);

        SubjectPublicKeyInfo decoded = SubjectPublicKeyInfo.getInstance(encoded);
        byte[] extracted = decoded.getPublicKeyData().getBytes();

        System.out.println("Decoded key length: " + extracted.length);

        boolean equals = Arrays.equals(publicKeyBytes, extracted);
        System.out.println("Keys match? " + equals);

        if (!equals) {
            System.out.println("Original: " + Hex.toHexString(publicKeyBytes));
            System.out.println("Decoded : " + Hex.toHexString(extracted));
        }


        // System.out.println("Tamaño clave original: " + publicKeyBytes.length);
        // System.out.println("Tamaño clave extraída: " + rawKey.length);
        // System.out.println("¿Coinciden los bytes originales con los extraídos? " +
        //     Arrays.equals(publicKeyBytes, rawKey));

    }

    public static byte[] loadKeyFromFile(String filename) throws IOException {
        return Files.readAllBytes(Paths.get("./src/test/java/com/paula/keycloak/crypto/" + filename));
    }
}
