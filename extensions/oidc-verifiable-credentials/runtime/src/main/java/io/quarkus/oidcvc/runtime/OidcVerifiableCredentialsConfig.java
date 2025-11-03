package io.quarkus.oidcvc.runtime;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;

/**
 * Configuration for OIDC Verifiable Credentials.
 */
@ConfigMapping(prefix = "quarkus.oidcvc")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface OidcVerifiableCredentialsConfig {

    /**
     * Request query parameter that contains a verifiable credential id
     */
    Optional<String> queryParamCredentialId();

    /**
     * Absolute credential issuer url
     */
    Optional<String> credentialIssuerUrl();

}
