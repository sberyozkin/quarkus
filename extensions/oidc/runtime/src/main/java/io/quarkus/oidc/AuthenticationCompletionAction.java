package io.quarkus.oidc;

import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

public interface AuthenticationCompletionAction {

    record AuthenticationCompletionContext(RoutingContext routingContext, AuthorizationCodeTokens tokens,
            TokenStateManager tokenStateManager) {
    }

    Uni<SecurityIdentity> action(AuthenticationCompletionContext authCompletionContext, SecurityIdentity identity,
            OidcRequestContext<SecurityIdentity> requestContext);
}
