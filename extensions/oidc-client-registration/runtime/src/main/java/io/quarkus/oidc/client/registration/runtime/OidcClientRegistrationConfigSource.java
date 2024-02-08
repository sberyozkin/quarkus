package io.quarkus.oidc.client.registration.runtime;

import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.spi.ConfigSource;

import io.quarkus.oidc.client.registration.OidcClientRegistration;
import io.quarkus.oidc.client.registration.RegisteredClient;

public class OidcClientRegistrationConfigSource implements ConfigSource {

    private OidcClientRegistration oidcClientReg;

    private volatile RegisteredClient registeredClient;

    public OidcClientRegistrationConfigSource(OidcClientRegistration oidcClientReg) {
        this.oidcClientReg = oidcClientReg;
    }

    @Override
    public String getName() {
        return "oidc-client-registration";
    }

    @Override
    public Map<String, String> getProperties() {
        return Map.of();
    }

    @Override
    public Set<String> getPropertyNames() {
        return Set.of("registered-client-id", "registered-client-secret");
    }

    @Override
    public String getValue(String propertyName) {

        if (registeredClient == null) {
            registeredClient = oidcClientReg.registerClient().await().indefinitely();
        }
        if (propertyName.equals("registered-client-id")) {
            return registeredClient.metadata().getClientId();
        } else if (propertyName.equals("registered-client-secret")) {
            return registeredClient.metadata().getClientSecret();
        }
        return null;
    }

}
