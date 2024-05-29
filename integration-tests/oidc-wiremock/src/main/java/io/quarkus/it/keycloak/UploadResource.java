package io.quarkus.it.keycloak;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import io.quarkus.security.identity.SecurityIdentity;

@Path("/upload")
public class UploadResource {

    @Inject
    SecurityIdentity identity;

    @GET
    @RolesAllowed("admin")
    @Path("/data")
    @Produces(MediaType.APPLICATION_JSON)
    public String bearerCertificateCustomValidator() {
        return "granted:" + identity.getRoles();
    }
}
