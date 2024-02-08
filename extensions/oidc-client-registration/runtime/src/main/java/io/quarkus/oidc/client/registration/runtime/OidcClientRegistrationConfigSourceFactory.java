package io.quarkus.oidc.client.registration.runtime;

import java.util.Collections;
import java.util.List;

import org.eclipse.microprofile.config.spi.ConfigSource;

import io.quarkus.arc.Arc;
import io.quarkus.arc.ArcContainer;
import io.quarkus.oidc.client.registration.OidcClientRegistration;
import io.quarkus.oidc.client.registration.OidcClientRegistrationConfig;
import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigSourceFactory.ConfigurableConfigSourceFactory;

public class OidcClientRegistrationConfigSourceFactory
        implements ConfigurableConfigSourceFactory<OidcClientRegistrationConfig> {
    @Override
    public Iterable<ConfigSource> getConfigSources(final ConfigSourceContext context,
            final OidcClientRegistrationConfig config) {
        if (config.authServerUrl.isPresent()) {
            ArcContainer container = Arc.container();
            OidcClientRegistration oidcClientReg = container.instance(OidcClientRegistration.class).get();
            return List.of(new OidcClientRegistrationConfigSource(oidcClientReg));
        } else {
            return Collections.emptyList();
        }
    }
}