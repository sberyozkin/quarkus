package io.quarkus.oidcvc.runtime;

import java.util.Optional;
import java.util.function.Supplier;

import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.common.runtime.OidcTlsSupport;
import io.quarkus.oidc.runtime.OidcConfig;
import io.quarkus.oidc.runtime.OidcTenantConfig;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata;
import io.quarkus.proxy.ProxyConfigurationRegistry;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.ext.web.client.WebClient;

@Recorder
public class OidcVerifiableCredentialsRecorder {

    private static final String CREDENTIAL_ISSUER_METADATA_PATH = "/.well-known/openid-credential-issuer";

    private final RuntimeValue<OidcConfig> oidcConfig;
    private final RuntimeValue<OidcVerifiableCredentialsConfig> oidcvcConfig;

    public OidcVerifiableCredentialsRecorder(final RuntimeValue<OidcConfig> oidcConfig,
            final RuntimeValue<OidcVerifiableCredentialsConfig> oidcvcConfig) {
        this.oidcConfig = oidcConfig;
        this.oidcvcConfig = oidcvcConfig;
    }

    public Supplier<VerifiableCredentialResolver> setup(Supplier<Vertx> vertx, Supplier<TlsConfigurationRegistry> registry,
            Supplier<ProxyConfigurationRegistry> proxyConfigurationRegistrySupplier) {
        OidcTenantConfig oidcTenantConfig = oidcConfig.getValue().namedTenants().get(OidcConfig.DEFAULT_TENANT_KEY);
        String authServerUrl = OidcCommonUtils.getAuthServerUrl(oidcTenantConfig);

        WebClientOptions options = new WebClientOptions();

        OidcCommonUtils.setHttpClientOptions(oidcTenantConfig, options,
                OidcTlsSupport.of(registry.get()).forConfig(oidcTenantConfig.tls()),
                proxyConfigurationRegistrySupplier.get());

        WebClient webClient = WebClient.create(new io.vertx.mutiny.core.Vertx(vertx.get()), options);

        String baseCredentialIssuerUrl = oidcvcConfig.getValue().credentialIssuerUrl().orElse(authServerUrl);

        String credentialIssuerMetadataUrl = OidcCommonUtils.getOidcEndpointUrl(baseCredentialIssuerUrl,
                Optional.of(CREDENTIAL_ISSUER_METADATA_PATH));

        OidcCredentialIssuerMetadata metadata = webClient.getAbs(credentialIssuerMetadataUrl).send().onItem()
                .transform(r -> new OidcCredentialIssuerMetadata(authServerUrl, r.bodyAsJsonObject()))
                .await().indefinitely();

        return new Supplier<VerifiableCredentialResolver>() {
            @Override
            public VerifiableCredentialResolver get() {
                return new VerifiableCredentialResolver(oidcvcConfig.getValue(), metadata, webClient);
            }
        };
    }
}
