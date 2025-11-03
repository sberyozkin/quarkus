package io.quarkus.oidcvc.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Build time configuration for OIDC Verifiable Credentials.
 */
@ConfigMapping(prefix = "quarkus.oidcvc")
@ConfigRoot
public interface OidcVerifiableCredentialsBuildTimeConfig {
    /**
     * If the OIDC Verifiable Credentials extension is enabled.
     */
    @WithDefault("true")
    boolean enabled();
}
