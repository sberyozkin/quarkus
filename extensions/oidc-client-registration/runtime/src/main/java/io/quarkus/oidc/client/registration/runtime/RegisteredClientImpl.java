package io.quarkus.oidc.client.registration.runtime;

import java.io.IOException;
import java.net.ConnectException;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;

import io.quarkus.oidc.client.registration.ClientMetadata;
import io.quarkus.oidc.client.registration.OidcClientRegistrationConfig;
import io.quarkus.oidc.client.registration.RegisteredClient;
import io.quarkus.oidc.common.OidcEndpoint;
import io.quarkus.oidc.common.OidcEndpoint.Type;
import io.quarkus.oidc.common.OidcRequestContextProperties;
import io.quarkus.oidc.common.OidcRequestFilter;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.groups.UniOnItem;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpRequest;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;

public class RegisteredClientImpl implements RegisteredClient {
    private static final Logger LOG = Logger.getLogger(RegisteredClientImpl.class);

    private static final String APPLICATION_JSON = "application/json";
    private static final String AUTHORIZATION_HEADER = String.valueOf(HttpHeaders.AUTHORIZATION);

    private final WebClient client;
    private final OidcClientRegistrationConfig oidcConfig;
    private final String registrationClientUri;
    private final String registrationToken;
    private final ClientMetadata registeredMetadata;
    private final Map<OidcEndpoint.Type, List<OidcRequestFilter>> filters;
    private volatile boolean closed;

    public RegisteredClientImpl(WebClient client, OidcClientRegistrationConfig oidcConfig,
            Map<Type, List<OidcRequestFilter>> oidcRequestFilters,
            ClientMetadata registeredMetadata, String registrationClientUri, String registrationToken) {
        this.client = client;
        this.oidcConfig = oidcConfig;
        this.registrationClientUri = registrationClientUri;
        this.registrationToken = registrationToken;
        this.registeredMetadata = registeredMetadata;
        this.filters = oidcRequestFilters;
    }

    @Override
    public ClientMetadata metadata() {
        checkClosed();
        return new ClientMetadata(registeredMetadata.toString());
    }

    @Override
    public Uni<RegisteredClient> read() {
        checkClosed();
        checkClientRequestUri();
        HttpRequest<Buffer> request = client.getAbs(registrationClientUri);
        request.putHeader(HttpHeaders.ACCEPT.toString(), APPLICATION_JSON);
        return makeRequest(request, Buffer.buffer())
                .transform(resp -> newRegisteredClient(resp, registeredMetadata));
    }

    @Override
    public Uni<RegisteredClient> update(ClientMetadata clientReg) {
        checkClosed();
        checkClientRequestUri();
        HttpRequest<Buffer> request = client.putAbs(registrationClientUri);
        request.putHeader(HttpHeaders.CONTENT_TYPE.toString(), APPLICATION_JSON);
        request.putHeader(HttpHeaders.ACCEPT.toString(), APPLICATION_JSON);
        return makeRequest(request, Buffer.buffer(clientReg.toString()))
                .transform(resp -> newRegisteredClient(resp, clientReg));
    }

    @Override
    public Uni<Void> delete() {
        checkClosed();
        checkClientRequestUri();

        return makeRequest(client.deleteAbs(registrationClientUri), Buffer.buffer())
                .transformToUni(resp -> deleteResponse(resp));
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            closed = true;
        }
    }

    private UniOnItem<HttpResponse<Buffer>> makeRequest(HttpRequest<Buffer> request, Buffer buffer) {
        if (registrationToken != null) {
            request.putHeader(AUTHORIZATION_HEADER, OidcConstants.BEARER_SCHEME + " " + registrationToken);
        }
        // Retry up to three times with a one-second delay between the retries if the connection is closed
        Uni<HttpResponse<Buffer>> response = filter(request, buffer).sendBuffer(buffer)
                .onFailure(ConnectException.class)
                .retry()
                .atMost(oidcConfig.connectionRetryCount)
                .onFailure().transform(t -> {
                    LOG.warn("OIDC Server is not available:", t.getCause() != null ? t.getCause() : t);
                    // don't wrap it to avoid information leak
                    return new OidcClientConfigurationException("OIDC Server is not available");
                });
        return response.onItem();
    }

    private HttpRequest<Buffer> filter(HttpRequest<Buffer> request, Buffer body) {
        if (!filters.isEmpty()) {
            OidcRequestContextProperties props = new OidcRequestContextProperties();
            for (OidcRequestFilter filter : OidcCommonUtils.getMatchingOidcRequestFilters(filters,
                    OidcEndpoint.Type.CLIENT_CONFIGURATION)) {
                filter.filter(request, body, props);
            }
        }
        return request;
    }

    private RegisteredClient newRegisteredClient(HttpResponse<Buffer> resp, ClientMetadata reg) {
        if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
            LOG.debug("Client has been succesfully registered");
            JsonObject json = resp.bodyAsJsonObject();

            String newRegistrationClientUri = json.getString(OidcConstants.REGISTRATION_CLIENT_URI);
            String newRegistrationToken = json.getString(OidcConstants.REGISTRATION_ACCESS_TOKEN);

            return new RegisteredClientImpl(client, oidcConfig, filters, new ClientMetadata(json),
                    (newRegistrationClientUri != null ? newRegistrationClientUri : registrationClientUri),
                    (newRegistrationToken != null ? newRegistrationToken : registrationToken));
        } else {
            String errorMessage = resp.bodyAsString();
            LOG.debugf("Client configuration has failed:  status: %d, error message: %s", resp.statusCode(),
                    errorMessage);
            throw new OidcClientConfigurationException(errorMessage);
        }
    }

    private Uni<Void> deleteResponse(HttpResponse<Buffer> resp) {
        if (resp.statusCode() == 200) {
            LOG.debug("Client has been succesfully deleted");
            return Uni.createFrom().voidItem();
        } else {
            String errorMessage = resp.bodyAsString();
            LOG.debugf("Client delete request has failed:  status: %d, error message: %s", resp.statusCode(),
                    errorMessage);
            return Uni.createFrom().voidItem();
        }
    }

    private void checkClosed() {
        if (closed) {
            throw new IllegalStateException("Registered OIDC Client is closed");
        }
    }

    private void checkClientRequestUri() {
        if (registrationClientUri == null) {
            throw new OidcClientConfigurationException(
                    "Registered OIDC Client can not make requests to the client configuration endpoint");
        }
    }

}
