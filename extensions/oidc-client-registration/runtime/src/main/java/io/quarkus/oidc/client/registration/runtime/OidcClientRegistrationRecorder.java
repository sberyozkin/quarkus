package io.quarkus.oidc.client.registration.runtime;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

import org.jboss.logging.Logger;

import io.quarkus.oidc.client.registration.ClientMetadata;
import io.quarkus.oidc.client.registration.OidcClientRegistration;
import io.quarkus.oidc.client.registration.OidcClientRegistrationConfig;
import io.quarkus.oidc.client.registration.OidcClientRegistrations;
import io.quarkus.oidc.client.registration.RegisteredClient;
import io.quarkus.oidc.common.OidcEndpoint;
import io.quarkus.oidc.common.OidcRequestContextProperties;
import io.quarkus.oidc.common.OidcRequestFilter;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.ext.web.client.WebClient;

@Recorder
public class OidcClientRegistrationRecorder {

    private static final Logger LOG = Logger.getLogger(OidcClientRegistrationRecorder.class);

    public OidcClientRegistrations setup(OidcClientRegistrationsConfig oidcClientRegsConfig,
            Supplier<Vertx> vertx, Supplier<TlsConfigurationRegistry> registrySupplier) {
        var defaultTlsConfiguration = registrySupplier.get().getDefault().orElse(null);

        OidcClientRegistration defaultClientReg = createOidcClientRegistration(oidcClientRegsConfig.defaultClientRegistration,
                defaultTlsConfiguration, vertx);

        Map<String, OidcClientRegistration> staticOidcClientRegs = new HashMap<>();

        for (Map.Entry<String, OidcClientRegistrationConfig> config : oidcClientRegsConfig.namedClientRegistrations
                .entrySet()) {
            staticOidcClientRegs.put(config.getKey(),
                    createOidcClientRegistration(config.getValue(), defaultTlsConfiguration, vertx));
        }

        return new OidcClientRegistrationsImpl(defaultClientReg, staticOidcClientRegs,
                new Function<OidcClientRegistrationConfig, Uni<OidcClientRegistration>>() {
                    @Override
                    public Uni<OidcClientRegistration> apply(OidcClientRegistrationConfig config) {
                        return createOidcClientRegistrationUni(config, defaultTlsConfiguration, vertx);
                    }
                });
    }

    public Supplier<OidcClientRegistration> createOidcClientRegistrationBean(OidcClientRegistrations oidcClientRegs) {
        return new Supplier<OidcClientRegistration>() {

            @Override
            public OidcClientRegistration get() {
                return oidcClientRegs.getClientRegistration();
            }
        };
    }

    public Supplier<OidcClientRegistrations> createOidcClientRegistrationsBean(OidcClientRegistrations oidcClientRegs) {
        return new Supplier<OidcClientRegistrations>() {

            @Override
            public OidcClientRegistrations get() {
                return oidcClientRegs;
            }
        };
    }

    protected static OidcClientRegistration createOidcClientRegistration(OidcClientRegistrationConfig oidcConfig,
            TlsConfiguration tlsConfig, Supplier<Vertx> vertxSupplier) {
        return createOidcClientRegistrationUni(oidcConfig, tlsConfig, vertxSupplier).await()
                .atMost(oidcConfig.connectionTimeout);
    }

    protected static Uni<OidcClientRegistration> createOidcClientRegistrationUni(OidcClientRegistrationConfig oidcConfig,
            TlsConfiguration tlsConfig, Supplier<Vertx> vertxSupplier) {
        if (!oidcConfig.clientRegistrationEnabled) {
            String message = String.format("'%s' client registration configuration is disabled", "");
            LOG.debug(message);
            return Uni.createFrom().item(new DisabledOidcClientRegistration(message));
        }
        try {
            if (oidcConfig.authServerUrl.isEmpty() && !OidcCommonUtils.isAbsoluteUrl(oidcConfig.registrationPath)) {
                throw new ConfigurationException(
                        "Either 'quarkus.oidc-client-registration.auth-server-url' or absolute 'quarkus.oidc-client-registration.registration-path' URL must be set");
            }
            OidcCommonUtils.verifyEndpointUrl(getEndpointUrl(oidcConfig));
        } catch (Throwable t) {
            LOG.error(t.getMessage());
            String message = String.format("'%s' client registration configuration is not initialized",
                    oidcConfig.id.orElse("Default"));
            return Uni.createFrom().failure(new RuntimeException(message));
        }

        WebClientOptions options = new WebClientOptions();

        OidcCommonUtils.setHttpClientOptions(oidcConfig, options, tlsConfig);

        final io.vertx.mutiny.core.Vertx vertx = new io.vertx.mutiny.core.Vertx(vertxSupplier.get());
        WebClient client = WebClient.create(vertx, options);

        Map<OidcEndpoint.Type, List<OidcRequestFilter>> oidcRequestFilters = OidcCommonUtils.getOidcRequestFilters();

        Uni<OidcConfigurationMetadata> tokenUrisUni = null;
        if (OidcCommonUtils.isAbsoluteUrl(oidcConfig.registrationPath)) {
            tokenUrisUni = Uni.createFrom().item(
                    new OidcConfigurationMetadata(oidcConfig.registrationPath.get()));
        } else {
            String authServerUriString = OidcCommonUtils.getAuthServerUrl(oidcConfig);
            if (!oidcConfig.discoveryEnabled.orElse(true)) {
                tokenUrisUni = Uni.createFrom()
                        .item(new OidcConfigurationMetadata(
                                OidcCommonUtils.getOidcEndpointUrl(authServerUriString, oidcConfig.registrationPath)));
            } else {
                tokenUrisUni = discoverRegistrationUri(client, oidcRequestFilters, authServerUriString.toString(), vertx,
                        oidcConfig);
            }
        }
        return tokenUrisUni.onItemOrFailure()
                .transform(new BiFunction<OidcConfigurationMetadata, Throwable, OidcClientRegistration>() {

                    @Override
                    public OidcClientRegistration apply(OidcConfigurationMetadata metadata, Throwable t) {
                        if (t != null) {
                            throw toOidcClientException(getEndpointUrl(oidcConfig), t);
                        }

                        if (metadata.tokenRegistrationUri == null) {
                            throw new ConfigurationException(
                                    "OpenId Connect Provider registration endpoint URL is not configured and can not be discovered");
                        }
                        return new OidcClientRegistrationImpl(client, metadata.tokenRegistrationUri,
                                oidcConfig,
                                oidcRequestFilters);
                    }

                });
    }

    private static String getEndpointUrl(OidcClientRegistrationConfig oidcConfig) {
        return oidcConfig.authServerUrl.isPresent() ? oidcConfig.authServerUrl.get() : oidcConfig.registrationPath.get();
    }

    private static Uni<OidcConfigurationMetadata> discoverRegistrationUri(WebClient client,
            Map<OidcEndpoint.Type, List<OidcRequestFilter>> oidcRequestFilters,
            String authServerUrl, io.vertx.mutiny.core.Vertx vertx, OidcClientRegistrationConfig oidcConfig) {
        final long connectionDelayInMillisecs = OidcCommonUtils.getConnectionDelayInMillis(oidcConfig);
        return OidcCommonUtils
                .discoverMetadata(client, oidcRequestFilters, new OidcRequestContextProperties(), authServerUrl,
                        connectionDelayInMillisecs, vertx,
                        oidcConfig.useBlockingDnsLookup)
                .onItem().transform(json -> new OidcConfigurationMetadata(json.getString("registration_endpoint")));
    }

    protected static OidcClientRegistrationException toOidcClientException(String authServerUrlString, Throwable cause) {
        return new OidcClientRegistrationException(OidcCommonUtils.formatConnectionErrorMessage(authServerUrlString), cause);
    }

    private static class DisabledOidcClientRegistration implements OidcClientRegistration {
        String message;

        DisabledOidcClientRegistration(String message) {
            this.message = message;
        }

        @Override
        public void close() throws IOException {
        }

        @Override
        public Uni<RegisteredClient> registerClient(ClientMetadata reg) {
            throw new DisabledOidcClientRegistrationException(message);
        }

        @Override
        public Uni<RegisteredClient> registerClient() {
            throw new DisabledOidcClientRegistrationException(message);
        }

        @Override
        public Multi<RegisteredClient> registerClients(List<ClientMetadata> regs) {
            throw new DisabledOidcClientRegistrationException(message);
        }

    }

    private static class OidcConfigurationMetadata {
        private final String tokenRegistrationUri;

        OidcConfigurationMetadata(String tokenRegistrationUri) {
            this.tokenRegistrationUri = tokenRegistrationUri;
        }
    }
}
