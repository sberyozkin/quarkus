package io.quarkus.it.bouncycastle;

import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

public class VaultConfigSource implements ConfigSource {

    @Override
    public Set<String> getPropertyNames() {
        return Set.of("configured-vault-password");
    }

    @Override
    public String getValue(String propertyName) {
        if (propertyName.equals("configured-vault-password")) {
            return "vaultpassword";
        } else {
            return null;
        }
    }

    @Override
    public String getName() {
        return "vault-http-config-source";
    }

}
