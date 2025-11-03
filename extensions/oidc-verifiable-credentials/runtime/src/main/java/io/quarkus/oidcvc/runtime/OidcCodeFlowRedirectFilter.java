package io.quarkus.oidcvc.runtime;

import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkus.oidc.OidcRedirectFilter;
import io.quarkus.oidc.Redirect;
import io.quarkus.oidc.Redirect.Location;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

@ApplicationScoped
@Redirect(Location.OIDC_AUTHORIZATION)
public class OidcCodeFlowRedirectFilter implements OidcRedirectFilter {

    @Inject
    VerifiableCredentialResolver resolver;

    @Override
    public void filter(OidcRedirectContext rc) {

        final Set<String> credentialIds = OidcVcUtils.extractCredentialIds(rc.routingContext(), resolver);
        if (credentialIds.isEmpty()) {
            return;
        }

        JsonArray creds = new JsonArray();

        String credentialId = credentialIds.iterator().next();

        JsonObject cred = new JsonObject();
        cred.put("type", "openid_credential");
        cred.put("credential_configuration_id", credentialId);
        creds.add(cred);

        rc.additionalQueryParams().add("authorization_details", creds.encode());

        String scope = resolver.getMetadata().getCredentialConfigurations().get(credentialId).scope();
        rc.additionalQueryParams().add("scope", scope);
    }
}
