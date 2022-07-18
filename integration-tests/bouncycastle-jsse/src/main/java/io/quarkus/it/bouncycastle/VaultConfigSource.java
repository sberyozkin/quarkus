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
        return "configured-vault-password".equals(propertyName) ? "vaultpassword" : null;
    }

    @Override
    public String getName() {
        return "vault";
    }

}
