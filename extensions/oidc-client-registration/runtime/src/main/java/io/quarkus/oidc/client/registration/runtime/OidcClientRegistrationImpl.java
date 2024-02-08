package io.quarkus.oidc.client.registration.runtime;

import java.io.IOException;
import java.net.ConnectException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.jboss.logging.Logger;

import io.quarkus.oidc.client.registration.ClientMetadata;
import io.quarkus.oidc.client.registration.OidcClientRegistration;
import io.quarkus.oidc.client.registration.OidcClientRegistrationConfig;
import io.quarkus.oidc.client.registration.RegisteredClient;
import io.quarkus.oidc.common.OidcEndpoint;
import io.quarkus.oidc.common.OidcEndpoint.Type;
import io.quarkus.oidc.common.OidcRequestContextProperties;
import io.quarkus.oidc.common.OidcRequestFilter;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.groups.UniOnItem;
import io.smallrye.mutiny.subscription.MultiEmitter;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpRequest;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;

public class OidcClientRegistrationImpl implements OidcClientRegistration {
    private static final Logger LOG = Logger.getLogger(OidcClientRegistrationImpl.class);
    private static final String APPLICATION_JSON = "application/json";
    private static final String AUTHORIZATION_HEADER = String.valueOf(HttpHeaders.AUTHORIZATION);

    private final WebClient client;
    private final String registrationUri;
    private final OidcClientRegistrationConfig oidcConfig;
    private final Map<OidcEndpoint.Type, List<OidcRequestFilter>> filters;
    private volatile boolean closed;

    public OidcClientRegistrationImpl(WebClient client, String registrationUri,
            OidcClientRegistrationConfig oidcConfig, Map<Type, List<OidcRequestFilter>> oidcRequestFilters) {
        this.client = client;
        this.registrationUri = registrationUri;
        this.oidcConfig = oidcConfig;
        this.filters = oidcRequestFilters;
    }

    @Override
    public Uni<RegisteredClient> registerClient() {
        JsonObject json = new JsonObject();
        if (oidcConfig.metadata.clientName.isPresent()) {
            json.put(OidcConstants.CLIENT_METADATA_CLIENT_NAME,
                    new JsonArray().add(oidcConfig.metadata.clientName.get()));
        }
        if (oidcConfig.metadata.redirectUri.isPresent()) {
            json.put(OidcConstants.CLIENT_METADATA_REDIRECT_URIS,
                    new JsonArray().add(oidcConfig.metadata.redirectUri.get()));
        }
        if (oidcConfig.metadata.postLogoutUri.isPresent()) {
            json.put(OidcConstants.POST_LOGOUT_REDIRECT_URI,
                    new JsonArray().add(oidcConfig.metadata.postLogoutUri.get()));
        }
        json.getMap().putAll(oidcConfig.metadata.extraProps);

        return registerClient(new ClientMetadata(json));
    }

    @Override
    public Uni<RegisteredClient> registerClient(ClientMetadata metadata) {
        LOG.debugf("Register client metadata: %s", metadata.toString());
        checkClosed();
        return postRequest(client.postAbs(registrationUri), metadata.toString())
                .transform(resp -> newRegisteredClient(resp));
    }

    @Override
    public Multi<RegisteredClient> registerClients(List<ClientMetadata> metadataList) {
        LOG.debugf("Register clients");
        checkClosed();
        return Multi.createFrom().emitter(new Consumer<MultiEmitter<? super RegisteredClient>>() {
            @Override
            public void accept(MultiEmitter<? super RegisteredClient> multiEmitter) {
                try {
                    AtomicInteger emitted = new AtomicInteger();
                    for (ClientMetadata metadata : metadataList) {
                        postRequest(client.postAbs(registrationUri), metadata.toString())
                                .transform(resp -> newRegisteredClient(resp))
                                .subscribe().with(new Consumer<RegisteredClient>() {
                                    @Override
                                    public void accept(RegisteredClient client) {
                                        multiEmitter.emit(client);
                                        if (emitted.incrementAndGet() == metadataList.size()) {
                                            multiEmitter.complete();
                                        }
                                    }
                                });
                    }
                } catch (Exception ex) {
                    multiEmitter.fail(ex);
                }
            }
        });
    }

    private UniOnItem<HttpResponse<Buffer>> postRequest(HttpRequest<Buffer> request, String clientRegJson) {
        request.putHeader(HttpHeaders.CONTENT_TYPE.toString(), APPLICATION_JSON);
        request.putHeader(HttpHeaders.ACCEPT.toString(), APPLICATION_JSON);
        if (oidcConfig.initialToken.orElse(null) != null) {
            request.putHeader(AUTHORIZATION_HEADER, OidcConstants.BEARER_SCHEME + " " + oidcConfig.initialToken.get());
        }
        // Retry up to three times with a one-second delay between the retries if the connection is closed
        Buffer buffer = Buffer.buffer(clientRegJson);
        Uni<HttpResponse<Buffer>> response = filter(request, buffer).sendBuffer(buffer)
                .onFailure(ConnectException.class)
                .retry()
                .atMost(oidcConfig.connectionRetryCount)
                .onFailure().transform(t -> {
                    LOG.warn("OIDC Server is not available:", t.getCause() != null ? t.getCause() : t);
                    // don't wrap it to avoid information leak
                    return new OidcClientRegistrationException("OIDC Server is not available");
                });
        return response.onItem();
    }

    private HttpRequest<Buffer> filter(HttpRequest<Buffer> request, Buffer body) {
        if (!filters.isEmpty()) {
            OidcRequestContextProperties props = new OidcRequestContextProperties();
            for (OidcRequestFilter filter : OidcCommonUtils.getMatchingOidcRequestFilters(filters,
                    OidcEndpoint.Type.CLIENT_REGISTRATION)) {
                filter.filter(request, body, props);
            }
        }
        return request;
    }

    private RegisteredClient newRegisteredClient(HttpResponse<Buffer> resp) {
        if (resp.statusCode() == 200 || resp.statusCode() == 201) {
            LOG.debug("Client has been succesfully registered");
            JsonObject json = resp.bodyAsJsonObject();

            String registrationClientUri = json.getString(OidcConstants.REGISTRATION_CLIENT_URI);
            String registrationToken = json.getString(OidcConstants.REGISTRATION_ACCESS_TOKEN);

            ClientMetadata metadata = new ClientMetadata(json);
            LOG.debugf("Response client metadata: %s", metadata.toString());

            return new RegisteredClientImpl(client, oidcConfig, filters, metadata,
                    registrationClientUri, registrationToken);
        } else {
            String errorMessage = resp.bodyAsString();
            LOG.debugf("Client registeration has failed:  status: %d, error message: %s", resp.statusCode(),
                    errorMessage);
            throw new OidcClientRegistrationException(errorMessage);
        }
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            client.close();
            closed = true;
        }
    }

    private void checkClosed() {
        if (closed) {
            throw new IllegalStateException("Oidc Client Registration is closed");
        }
    }

}
