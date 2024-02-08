package io.quarkus.oidc.client.registration.runtime;

@SuppressWarnings("serial")
public class OidcClientRegistrationException extends RuntimeException {
    public OidcClientRegistrationException() {

    }

    public OidcClientRegistrationException(String errorMessage) {
        this(errorMessage, null);
    }

    public OidcClientRegistrationException(Throwable cause) {
        this(null, cause);
    }

    public OidcClientRegistrationException(String errorMessage, Throwable cause) {
        super(errorMessage, cause);
    }
}
