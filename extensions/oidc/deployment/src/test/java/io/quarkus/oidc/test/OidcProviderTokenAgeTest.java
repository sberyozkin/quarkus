package io.quarkus.oidc.test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Instant;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.runtime.JsonWebKeySet;
import io.quarkus.oidc.runtime.OidcProvider;
import io.quarkus.oidc.runtime.TokenVerificationResult;
import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.jwk.RsaJsonWebKey;
import io.smallrye.jwt.auth.InvalidJWTException;
import io.smallrye.jwt.build.Jwt;

/**
 * Verification of the tokens which have no `iat` claim.
 * <p>
 * This test is a deployment test because only the application configuration can stop
 * the SmallRye JWT build API from adding a default `iat` claim to the generated tokens.
 */
public class OidcProviderTokenAgeTest {

    @RegisterExtension
    static final QuarkusUnitTest test = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addAsResource(new StringAsset("""
                            quarkus.keycloak.devservices.enabled=false
                            quarkus.oidc.tenant-enabled=false
                            # the token created by this test must have no 'iat' claim
                            smallrye.jwt.new-token.add-default-claims=false
                            """),
                            "application.properties"));

    @Test
    public void testAge() throws Exception {
        RsaJsonWebKey rsaKey = RsaJsonWebKey.builder(2048).build();

        // 'smallrye.jwt.new-token.add-default-claims' is set to 'false', so this token has 'exp' but no 'iat'
        String token = Jwt.claims().expiresAt(Instant.now().plusSeconds(1000)).sign(rsaKey.privateKey());

        JsonWebKeySet jwkSet = new JsonWebKeySet(io.smallrye.jwk.JsonWebKeySet.of(rsaKey).asJsonString());

        OidcTenantConfig oidcConfig = new OidcTenantConfig();
        oidcConfig.token.issuedAtRequired = false;

        try (OidcProvider provider = new OidcProvider(null, oidcConfig, jwkSet)) {
            TokenVerificationResult result = provider.verifyJwtToken(token, false, false, null);
            assertNull(result.localVerificationResult().getString(Claims.iat.name()));
        }

        OidcTenantConfig oidcConfigRequireAge = new OidcTenantConfig();
        oidcConfigRequireAge.token.issuedAtRequired = true;

        try (OidcProvider provider = new OidcProvider(null, oidcConfigRequireAge, jwkSet)) {
            try {
                provider.verifyJwtToken(token, false, false, null);
                fail("InvalidJWTException expected");
            } catch (InvalidJWTException ex) {
                assertTrue(ex.getMessage().contains("iat"));
            }
        }
    }
}
