package io.quarkus.oidcvc.runtime;

import java.util.Set;
import java.util.function.Function;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.AuthenticationCompletionAction;
import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.oidc.runtime.TenantConfigContext;
import io.quarkus.oidcvc.VerifiableCredential;
import io.quarkus.security.AuthenticationRedirectException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

@ApplicationScoped
public class VerifiableCredentialAction implements AuthenticationCompletionAction {

    @Inject
    VerifiableCredentialResolver resolver;

    @Override
    public Uni<SecurityIdentity> action(AuthenticationCompletionContext ac, SecurityIdentity identity,
            OidcRequestContext<SecurityIdentity> requestContext) {

        AccessTokenCredential accessTokenCred = identity.getCredential(AccessTokenCredential.class);
        if (accessTokenCred == null || accessTokenCred.isOpaque()) {
            // TODO: If the then is opaque then we can check scopes in the introspection response
            return Uni.createFrom().item(identity);
        }

        final TenantConfigContext configContext = ac.routingContext().get(TenantConfigContext.class.getName());

        final String credentialId = extractCredentialId(ac, configContext.getOidcTenantConfig());
        if (credentialId == null) {
            return Uni.createFrom().item(identity);
        }

        //TODO: handle an opaque token
        JsonObject jwt = OidcUtils.decodeJwtContent(accessTokenCred.getToken());
        if (!OidcVcUtils.isTokenCredentialScopeAvailable(resolver, jwt, credentialId)) {
            return OidcUtils.removeSessionCookie(ac.routingContext(),
                    configContext.getOidcTenantConfig(), ac.tokenStateManager()).onItem()
                    .transformToUni(new Function<Void, Uni<? extends SecurityIdentity>>() {

                        @Override
                        public Uni<SecurityIdentity> apply(Void t) {
                            String redirectUri = ac.routingContext().request().absoluteURI();
                            //TODO: consider adding credential scopes already supported by the current access token
                            // Or, perhaps it is simpler to request all available identity scopes at the initial wallet login
                            return Uni.createFrom().failure(
                                    new AuthenticationRedirectException(redirectUri));
                        }

                    });
        }

        return OidcVcUtils.getVerifiableCredential(ac.routingContext(), ac.tokens().getAccessToken(),
                resolver.getMetadata(), credentialId, resolver.getWebClient())
                .onItem()
                .transform(
                        vc -> addCredentialToIdentity(ac.routingContext(), identity, vc));

    }

    private static SecurityIdentity addCredentialToIdentity(RoutingContext context, SecurityIdentity identity,
            VerifiableCredential vc) {

        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder(identity);
        builder.addAttribute(VerifiableCredential.class.getName(), vc);
        return builder.build();
    }

    private String extractCredentialId(AuthenticationCompletionContext ac, OidcTenantConfig oidcConfig) {
        Set<String> credentialIds = OidcVcUtils.extractCredentialIds(ac.routingContext(), resolver);
        return credentialIds.isEmpty() ? null : credentialIds.iterator().next();
    }

}
