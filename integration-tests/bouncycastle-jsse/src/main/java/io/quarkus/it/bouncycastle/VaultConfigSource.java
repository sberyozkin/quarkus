package io.quarkus.it.bouncycastle;

import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

import io.quarkiverse.filevault.runtime.FileVaultConfig;
import io.quarkiverse.filevault.runtime.FileVaultCredentialsProvider;

public class VaultConfigSource implements ConfigSource {

    private static final String SHORT_VAULT_NAME = "vertxhttp";
    private static final String FULL_VAULT_NAME = "quarkus.file.vault.provider." + SHORT_VAULT_NAME;

    FileVaultCredentialsProvider fileVaultCredentialsProvider;

    public VaultConfigSource() {
        FileVaultConfig fileVaultConfig = new FileVaultConfig();
        // Vault secret is `vaultpassword`
        // Here it is shown in the encrypted form. First we have built `quarkus-file-vault-utils`,
        // run it as `java -jar target/quarkus-app/quarkus-run.jar -p vaultpassword`
        // which auto-generated an encryption key (as `e3TdzFktFTbz6YHJYSHrGw`) and encrypted the vault secret as
        // `DM-Z7qGLmKM_TkPeMEKOPeBr5LDDBjbH7HYBDW748ms8K0IcH-QFmPJm`.

        // So we configure FileVault with the `path` to the vault keystore (`vault.p12`), as well as the `encryption-key` and the encrypted
        // vault `secret`. `encryption-key` remains the ***only value*** in clear text in this ConfigSource.

        fileVaultConfig.provider = Map.of(SHORT_VAULT_NAME,
                Map.of("path", "vault.p12",
                        "encryption-key", "e3TdzFktFTbz6YHJYSHrGw",
                        "secret", "DM-Z7qGLmKM_TkPeMEKOPeBr5LDDBjbH7HYBDW748ms8K0IcH-QFmPJm"));
        // Initialize FileVaultCredentialsProvider
        fileVaultCredentialsProvider = new FileVaultCredentialsProvider(fileVaultConfig);
    }

    @Override
    public Set<String> getPropertyNames() {
        // these 2 properties represent Vert.x HTTP keystore and truststore passwords and
        // will be read read from the file vault, they are not managed directly by this ConfigSource
        return Set.of("keystore_password_alias", "truststore_password_alias");
    }

    @Override
    public String getValue(String propertyName) {
        if (propertyName.equals("keystore_password_alias") || propertyName.equals("truststore_password_alias")) {
            return fileVaultCredentialsProvider.getCredentials(FULL_VAULT_NAME).get(propertyName);
        } else {
            return null;
        }
    }

    @Override
    public String getName() {
        return "vault-http-config-source";
    }

}
