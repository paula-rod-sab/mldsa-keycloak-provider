package com.paula.keycloak.crypto.keys;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.openquantumsafe.Signature;

@SuppressWarnings("rawtypes")
public class MLDSAKeyProviderFactory implements KeyProviderFactory {

    public static final String ID = "ml-dsa-key-provider";
    
    private byte[] publicKey;
    private byte[] privateKey;

    private static final String PUBLIC_KEY_FILE = "mldsa_public.key";
    private static final String PRIVATE_KEY_FILE = "mldsa_private.key";

    @Override
    public void init(Config.Scope config) {
        try {
            if (filesExist()) {
                loadKeysFromFiles();
                System.out.println("[MLDSAKeyProviderFactory] Keys loaded from files.");
            } else {
                generateAndSaveKeys();
                System.out.println("[MLDSAKeyProviderFactory] Keys generated and saved.");
            }
        } catch (IOException e) {
            throw new RuntimeException("Error managing key files", e);
        }
    }

    private boolean filesExist() {
        return new File(PUBLIC_KEY_FILE).exists() && new File(PRIVATE_KEY_FILE).exists();
    }

    private void loadKeysFromFiles() throws IOException {
        publicKey = Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE));
        privateKey = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
    }

    private void generateAndSaveKeys() throws IOException {
        Signature signer = new Signature("ML-DSA-44");

        publicKey = signer.generate_keypair();
        privateKey = signer.export_secret_key();

        Files.write(Paths.get(PUBLIC_KEY_FILE), publicKey);
        Files.write(Paths.get(PRIVATE_KEY_FILE), privateKey);

        signer.dispose_sig();
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return "ML-DSA (post-quantum) key provider using liboqs-java.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public KeyProvider create(KeycloakSession session, ComponentModel model) {
        return new MLDSAKeyProvider(publicKey, privateKey);
    }
    
}
