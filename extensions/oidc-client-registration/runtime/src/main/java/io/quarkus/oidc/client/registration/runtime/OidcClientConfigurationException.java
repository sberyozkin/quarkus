package io.quarkus.oidc.client.registration.runtime;

@SuppressWarnings("serial")
public class OidcClientConfigurationException extends RuntimeException {
    public OidcClientConfigurationException() {

    }

    public OidcClientConfigurationException(String errorMessage) {
        this(errorMessage, null);
    }

    public OidcClientConfigurationException(Throwable cause) {
        this(null, cause);
    }

    public OidcClientConfigurationException(String errorMessage, Throwable cause) {
        super(errorMessage, cause);
    }
}
