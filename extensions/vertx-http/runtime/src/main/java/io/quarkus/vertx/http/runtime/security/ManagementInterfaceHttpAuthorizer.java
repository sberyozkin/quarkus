package io.quarkus.vertx.http.runtime.security;

import java.util.List;

import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.spi.runtime.AuthorizationController;

/**
 * Class that is responsible for running the Management HTTP based permission checks
 */
public class ManagementInterfaceHttpAuthorizer extends AbstractHttpAuthorizer {

    public ManagementInterfaceHttpAuthorizer(HttpAuthenticator httpAuthenticator,
            IdentityProviderManager identityProviderManager,
            AuthorizationController controller, HttpSecurityPolicy installedPolicy) {
        super(httpAuthenticator, identityProviderManager, controller, List.of(installedPolicy));
    }
}
