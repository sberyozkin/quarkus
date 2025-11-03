package io.quarkus.oidcvc.runtime;

import io.quarkus.oidcvc.OidcCredentialIssuerMetadata;
import io.vertx.mutiny.ext.web.client.WebClient;

public class VerifiableCredentialResolver {
    private final OidcVerifiableCredentialsConfig oidcvcConfig;
    private final OidcCredentialIssuerMetadata metadata;
    private final WebClient webClient;

    public VerifiableCredentialResolver(OidcVerifiableCredentialsConfig oidcvcConfig, OidcCredentialIssuerMetadata metadata,
            WebClient webClient) {
        this.oidcvcConfig = oidcvcConfig;
        this.metadata = metadata;
        this.webClient = webClient;
    }

    public OidcCredentialIssuerMetadata getMetadata() {
        return metadata;
    }

    public WebClient getWebClient() {
        return webClient;
    }

    public OidcVerifiableCredentialsConfig getOidcvcConfig() {
        return oidcvcConfig;
    }

}
