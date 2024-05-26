package io.quarkus.it.keycloak;

import java.net.URI;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

import org.eclipse.microprofile.rest.client.inject.RestClient;

import io.smallrye.mutiny.Uni;

@Path("/frontend")
public class FrontendResource {
    @Inject
    @RestClient
    AccessTokenPropagationService accessTokenPropagationService;

    AccessTokenPropagationService builtAccessTokenPropagationService;

    @Inject
    @RestClient
    IdTokenPropagationService idTokenPropagationService;

    @Inject
    @RestClient
    ServiceWithoutToken serviceWithoutToken;

    @PostConstruct
    public void init() {
        builtAccessTokenPropagationService = QuarkusRestClientBuilder.newBuilder()
                .baseUri(new URI("http://localhost:8081/protected"))
                .build(AccessTokenPropagationService.class);
    }

    @GET
    @Path("access-token-propagation")
    @Produces("text/plain")
    @RolesAllowed("user")
    public Uni<String> userNameAccessTokenPropagation() {
        return accessTokenPropagationService.getUserName();
    }

    @GET
    @Path("id-token-propagation")
    @Produces("text/plain")
    @RolesAllowed("user")
    public Uni<String> userNameIdTokenPropagation() {
        return idTokenPropagationService.getUserName();
    }

    @GET
    @Path("service-without-token")
    @Produces("text/plain")
    public Uni<String> userNameServiceWithoutToken() {
        return serviceWithoutToken.getUserName();
    }
}
