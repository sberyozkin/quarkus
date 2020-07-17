package io.quarkus.jwt.test;

import java.util.Optional;

import javax.inject.Inject;
import javax.json.JsonString;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;

import io.quarkus.security.Authenticated;

@Path("/endp")
@Authenticated
public class JsonStringSingletonEndpoint {
    @Inject
    @Claim(standard = Claims.upn)
    Optional<JsonString> upn;

    @GET
    @Path("upns")
    @Produces(MediaType.TEXT_PLAIN)
    public String verifyInjectedUpn() {
        return upn.get().getString();
    }
}
