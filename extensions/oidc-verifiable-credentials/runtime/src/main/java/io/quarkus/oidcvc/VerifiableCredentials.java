package io.quarkus.oidcvc;

import java.util.List;

public class VerifiableCredentials {
    private final List<VerifiableCredential> credentials;

    public VerifiableCredentials() {
        this(List.of());
    }

    public VerifiableCredentials(List<VerifiableCredential> credentials) {
        this.credentials = credentials;
    }

    public List<VerifiableCredential> getCredentials() {
        return credentials;
    }
}
