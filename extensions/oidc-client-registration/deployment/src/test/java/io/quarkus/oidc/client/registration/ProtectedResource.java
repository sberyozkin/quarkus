package io.quarkus.oidc.client.registration;

import java.security.Principal;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import io.quarkus.security.Authenticated;

@Path("/protected")
@Authenticated
public class ProtectedResource {

    @Inject
    Principal principal;

    @GET
    public String principalName() {
        return principal.getName();
    }

    @GET
    @Path("/dynamic")
    public String dynamicPrincipalName() {
        return principal.getName();
    }

    @GET
    @Path("/multi1")
    public String principalNameMulti1() {
        return principal.getName();
    }

    @GET
    @Path("/multi2")
    public String principalNameMulti2() {
        return principal.getName();
    }
}
