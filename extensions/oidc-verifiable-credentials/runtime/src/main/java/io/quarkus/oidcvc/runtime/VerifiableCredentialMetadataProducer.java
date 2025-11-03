package io.quarkus.oidcvc.runtime;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

import io.quarkus.oidcvc.OidcCredentialIssuerMetadata;

public class VerifiableCredentialMetadataProducer {
    @Inject
    VerifiableCredentialResolver resolver;

    @Produces
    OidcCredentialIssuerMetadata metadata() {
        return resolver.getMetadata();
    }
}
