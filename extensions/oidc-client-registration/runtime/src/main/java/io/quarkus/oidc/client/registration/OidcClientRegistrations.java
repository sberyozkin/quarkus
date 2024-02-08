package io.quarkus.oidc.client.registration;

import java.io.Closeable;

import io.smallrye.mutiny.Uni;

public interface OidcClientRegistrations extends Closeable {
    OidcClientRegistration getClientRegistration();

    OidcClientRegistration getClientRegistration(String id);

    Uni<OidcClientRegistration> newClientRegistration(OidcClientRegistrationConfig oidcConfig);

}
