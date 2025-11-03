package io.quarkus.oidcvc.runtime;

import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import io.quarkus.oidcvc.VerifiableCredential;
import io.quarkus.oidcvc.VerifiableCredentials;
import io.quarkus.security.identity.SecurityIdentity;

@RequestScoped
public class VerifiableCredentialProducer {
    private static final Logger LOG = Logger.getLogger(VerifiableCredentialProducer.class);
    @Inject
    SecurityIdentity identity;

    @Produces
    @RequestScoped
    VerifiableCredential credential() {
        VerifiableCredential cred = identity.getAttribute(VerifiableCredential.class.getName());
        if (cred == null) {
            LOG.error("Credential is null");
            cred = new VerifiableCredential();
        }
        return cred;
    }

    @Produces
    @RequestScoped
    VerifiableCredentials credentials() {
        VerifiableCredentials creds = identity.getAttribute(VerifiableCredentials.class.getName());
        if (creds == null) {
            LOG.error("Credentials is null");
            creds = new VerifiableCredentials();
        }
        return creds;
    }
}
