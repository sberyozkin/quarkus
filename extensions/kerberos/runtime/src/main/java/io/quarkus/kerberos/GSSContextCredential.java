package io.quarkus.kerberos;

import org.ietf.jgss.GSSContext;

import io.quarkus.security.credential.Credential;

public class GSSContextCredential implements Credential {
    private GSSContext gssContext;

    public GSSContextCredential() {

    }

    public GSSContextCredential(GSSContext gssContext) {
        this.gssContext = gssContext;
    }

    public GSSContext getGssContext() {
        return gssContext;
    }
}
