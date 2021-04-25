package io.quarkus.it.keycloak;

import java.security.Principal;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import org.jboss.logging.Logger;

import io.quarkus.security.Authenticated;

@Path("/protected")
@Authenticated
public class ProtectedResource {

    private static final Logger LOG = Logger.getLogger(ProtectedResource.class);

    @Inject
    Principal principal;

    @GET
    @RolesAllowed("user")
    @Produces("text/plain")
    @Path("userName")
    public String principalName() {
        String principalName = principal.getName();
        LOG.errorf("ProtectedResource:getUseName returns '%s'", principalName);
        return principalName;
    }

    @GET
    @RolesAllowed("user")
    @Produces("text/plain")
    @Path("userNameReactive")
    public String principalNameReactive() {
        return principal.getName();
    }
}
