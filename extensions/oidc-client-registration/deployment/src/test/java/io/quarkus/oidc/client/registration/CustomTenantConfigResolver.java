package io.quarkus.oidc.client.registration;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.OidcTenantConfig.ApplicationType;
import io.quarkus.oidc.TenantConfigResolver;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

@Singleton
public class CustomTenantConfigResolver implements TenantConfigResolver {

    @Inject
    OidcClientRegistration clientReg;

    @Inject
    OidcClientRegistrations clientRegs;

    @Inject
    @ConfigProperty(name = "quarkus.oidc.auth-server-url")
    String authServerUrl;

    volatile RegisteredClient regClientOnStartup;
    volatile RegisteredClient regClientDynamically;

    volatile Map<String, RegisteredClient> regClientsMulti;

    void onStartup(@Observes StartupEvent event) {

        regClientOnStartup = clientReg.registerClient().await().indefinitely();

        ClientMetadata clientMetadataMulti1 = new ClientMetadata(new JsonObject().put(
                OidcConstants.CLIENT_METADATA_REDIRECT_URIS,
                new JsonArray().add("http://localhost:8081/protected/multi1")));
        ClientMetadata clientMetadataMulti2 = new ClientMetadata(new JsonObject().put(
                OidcConstants.CLIENT_METADATA_REDIRECT_URIS,
                new JsonArray().add("http://localhost:8081/protected/multi2")));

        Uni<Map<String, RegisteredClient>> clients = clientReg
                .registerClients(List.of(clientMetadataMulti1, clientMetadataMulti2))
                .collect().asMap(r -> URI.create(r.metadata().getRedirectUris().get(0)).getPath(), r -> r);
        regClientsMulti = clients.await().indefinitely();
    }

    void onShutdown(@Observes ShutdownEvent event) {

        if (regClientOnStartup != null) {
            regClientOnStartup.delete().await().indefinitely();
        }
        if (regClientDynamically != null) {
            regClientDynamically.delete().await().indefinitely();
        }
        if (regClientsMulti != null) {
            for (RegisteredClient client : regClientsMulti.values()) {
                client.delete().await().indefinitely();
            }
        }
    }

    @Override
    public Uni<OidcTenantConfig> resolve(RoutingContext routingContext,
            OidcRequestContext<OidcTenantConfig> requestContext) {
        if (routingContext.request().path().endsWith("/protected")) {
            OidcTenantConfig oidcConfig = new OidcTenantConfig();
            oidcConfig.setTenantId("registered-client");
            oidcConfig.setAuthServerUrl(authServerUrl);
            oidcConfig.setApplicationType(ApplicationType.WEB_APP);
            oidcConfig.setClientId(regClientOnStartup.metadata().getClientId());
            oidcConfig.getCredentials().setSecret(regClientOnStartup.metadata().getClientSecret());

            String redirectUri = regClientOnStartup.metadata().getRedirectUris().get(0);
            oidcConfig.getAuthentication().setRedirectPath(URI.create(redirectUri).getPath());
            return Uni.createFrom().item(oidcConfig);
        } else if (routingContext.request().path().endsWith("/protected/dynamic")) {
            OidcClientRegistrationConfig clientRegConfig = new OidcClientRegistrationConfig();
            clientRegConfig.authServerUrl = Optional.of(authServerUrl);
            clientRegConfig.metadata.redirectUri = Optional.of("http://localhost:8081/protected/dynamic");
            return clientRegs.newClientRegistration(clientRegConfig)
                    .onItem().transformToUni(cfg -> cfg.registerClient())
                    .onItem().transform(regClient -> newOidcTenantConfig(regClient));
        } else if (routingContext.request().path().endsWith("/protected/multi1")) {
            OidcTenantConfig oidcConfig = new OidcTenantConfig();
            oidcConfig.setTenantId("registered-client-multi1");
            oidcConfig.setAuthServerUrl(authServerUrl);
            oidcConfig.setApplicationType(ApplicationType.WEB_APP);

            ClientMetadata metadata = regClientsMulti.get("/protected/multi1").metadata();
            oidcConfig.setClientId(metadata.getClientId());
            oidcConfig.getCredentials().setSecret(metadata.getClientSecret());
            String redirectUri = metadata.getRedirectUris().get(0);
            oidcConfig.getAuthentication().setRedirectPath(URI.create(redirectUri).getPath());
            return Uni.createFrom().item(oidcConfig);
        } else if (routingContext.request().path().endsWith("/protected/multi2")) {
            OidcTenantConfig oidcConfig = new OidcTenantConfig();
            oidcConfig.setTenantId("registered-client-multi2");
            oidcConfig.setAuthServerUrl(authServerUrl);
            oidcConfig.setApplicationType(ApplicationType.WEB_APP);

            ClientMetadata metadata = regClientsMulti.get("/protected/multi2").metadata();
            oidcConfig.setClientId(metadata.getClientId());
            oidcConfig.getCredentials().setSecret(metadata.getClientSecret());
            String redirectUri = metadata.getRedirectUris().get(0);
            oidcConfig.getAuthentication().setRedirectPath(URI.create(redirectUri).getPath());
            return Uni.createFrom().item(oidcConfig);
        }

        return null;
    }

    private OidcTenantConfig newOidcTenantConfig(RegisteredClient newClient) {

        regClientDynamically = newClient;

        OidcTenantConfig oidcConfig = new OidcTenantConfig();
        oidcConfig.setTenantId("registered-client-dynamically");
        oidcConfig.setAuthServerUrl(authServerUrl);
        oidcConfig.setApplicationType(ApplicationType.WEB_APP);
        oidcConfig.setClientId(regClientDynamically.metadata().getClientId());
        oidcConfig.getCredentials().setSecret(regClientDynamically.metadata().getClientSecret());

        String redirectUri = regClientDynamically.metadata().getRedirectUris().get(0);
        oidcConfig.getAuthentication().setRedirectPath(URI.create(redirectUri).getPath());

        return oidcConfig;
    }

}
