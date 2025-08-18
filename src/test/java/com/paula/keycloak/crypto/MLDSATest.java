package com.paula.keycloak.crypto;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.openquantumsafe.Common;
import org.openquantumsafe.Signature;

public class MLDSATest {
    public static void main(String[] args) throws IOException {

        byte[] message = "This is the message to sign".getBytes();


        byte[] signer_public_key = loadKeyFromFile("public.key");
        byte[] signer_private_key = loadKeyFromFile("private.key");

        Signature signer = new Signature("ML-DSA-44", signer_private_key);

        System.out.println("Signer public key:");
        System.out.println(Common.chop_hex(signer_public_key));

        byte[] signature = signer.sign(message);
        System.out.println("\nSignature:");
        System.out.println(Common.chop_hex(signature));

        Signature verifier = new Signature("ML-DSA-44");
        boolean is_valid = verifier.verify(message, signature, signer_public_key);
        System.out.println("\nValid signature? " + is_valid);

        signer.dispose_sig();
        verifier.dispose_sig();
    }

    public static void saveKeyToFile(String filename, byte[] key) throws IOException {
        Files.write(Paths.get("./src/test/java/com/paula/keycloak/crypto/" + filename), key);
    }

    public static byte[] loadKeyFromFile(String filename) throws IOException {
        return Files.readAllBytes(Paths.get("./src/test/java/com/paula/keycloak/crypto/" + filename));
    }
}