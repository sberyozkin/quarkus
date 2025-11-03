package io.quarkus.oidcvc.runtime;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

import com.authlete.sd.SDJWT;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.runtime.OidcProvider;
import io.quarkus.oidc.runtime.TenantConfigContext;
import io.quarkus.oidc.runtime.TokenVerificationResult;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata.CredentialConfiguration;
import io.quarkus.oidcvc.VerifiableCredential;
import io.quarkus.oidcvc.VerifiableCredential.Disclosure;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.groups.UniOnItem;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;

public final class OidcVcUtils {
    private OidcVcUtils() {

    }

    public static Uni<VerifiableCredential> getVerifiableCredential(RoutingContext rc, String credentialAccessToken,
            OidcCredentialIssuerMetadata metadata, String credentialId,
            WebClient webClient) {

        final TenantConfigContext configContext = rc.get(TenantConfigContext.class.getName());

        EllipticCurveJsonWebKey ecJwkKey = createECJwk();

        UniOnItem<HttpResponse<Buffer>> nonceHttpResponseUni = webClient
                .postAbs(metadata.getNonceEndpoint()).send().onItem();

        return nonceHttpResponseUni
                .transformToUni(new Function<HttpResponse<Buffer>, Uni<? extends VerifiableCredential>>() {

                    @Override
                    public Uni<VerifiableCredential> apply(HttpResponse<Buffer> nonceResp) {
                        final JsonObject credentialRequestJson = createCredentialRequest(credentialId,
                                configContext.getOidcTenantConfig(), nonceResp.bodyAsJsonObject(), ecJwkKey,
                                metadata.getAuthServerUrl());

                        UniOnItem<HttpResponse<Buffer>> credHttpResponseUni = webClient
                                .postAbs(metadata.getCredentialEndpoint())
                                .bearerTokenAuthentication(credentialAccessToken)
                                .sendJsonObject(credentialRequestJson)
                                .onItem();

                        return credHttpResponseUni
                                .transform(
                                        credR -> getVerifiedCredential(credR.bodyAsJsonObject(), configContext.provider(),
                                                configContext.getOidcTenantConfig(), ecJwkKey, credentialId));
                    }

                });
    }

    private static VerifiableCredential getVerifiedCredential(JsonObject credsJson, OidcProvider provider,
            OidcTenantConfig oidcConfig,
            PublicJsonWebKey jwk,
            String credentialId) {
        JsonArray creds = credsJson.getJsonArray("credentials");
        JsonObject cred = creds.getJsonObject(0);

        return verifyCred(provider, oidcConfig, cred, jwk, credentialId);
    }

    private static JsonObject createCredentialRequest(String credentialId, OidcTenantConfig oidcConfig,
            JsonObject nonceResponse, PublicJsonWebKey jwk, String authServerUrl) {

        JsonObject cred = new JsonObject();
        cred.put("credential_identifier", credentialId);
        JsonObject proofs = new JsonObject();
        JsonArray jwt = new JsonArray();
        jwt.add(generateProofJwt(oidcConfig, extractNonce(nonceResponse), jwk, authServerUrl));
        proofs.put("jwt", jwt);
        cred.put("proofs", proofs);
        return cred;
    }

    private static String extractNonce(JsonObject nonceJson) {
        return nonceJson.getString("c_nonce");
    }

    private static String generateProofJwt(OidcTenantConfig oidcConfig, String nonce, PublicJsonWebKey jwk,
            String authServerUrl) {
        String jwt = Jwt.issuer(oidcConfig.clientId().get())
                .audience(authServerUrl)
                .claim("nonce", nonce)
                .jws().type("openid4vci-proof+jwt").jwk(jwk.getPublicKey())
                .sign(jwk.getPrivateKey());

        return jwt;

    }

    private static EllipticCurveJsonWebKey createECJwk() {
        try {
            return EcJwkGenerator.generateJwk(EllipticCurves.P256);
        } catch (JoseException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static VerifiableCredential verifyCred(OidcProvider provider, OidcTenantConfig oidcConfig, JsonObject credential,
            PublicJsonWebKey jwk, String credentialId) {

        String sdJwtString = credential.getString("credential");

        SDJWT sdJwt = SDJWT.parse(sdJwtString);

        // Credential JWT Signature

        TokenVerificationResult credentialJwtResult = verifyCredentialJwt(provider, oidcConfig, sdJwt.getCredentialJwt());

        // Basic disclosure verification for now

        JsonObject jwt = credentialJwtResult.localVerificationResult();
        JsonArray digests = jwt.getJsonArray("_sd");
        Set<String> digestStrings = new HashSet<>();
        for (int i = 0; i < digests.size(); i++) {
            digestStrings.add(digests.getString(i));
        }
        List<Disclosure> verifiedDisclosures = new ArrayList<>();
        for (com.authlete.sd.Disclosure d : sdJwt.getDisclosures()) {
            if (digestStrings.contains(d.digest())) {
                verifiedDisclosures.add(new Disclosure(d.getClaimName(), d.getClaimValue()));
            }
        }

        String privateKeyJwk = jwk.toJson(OutputControlLevel.INCLUDE_PRIVATE);

        return new VerifiableCredential(credentialId, sdJwtString, privateKeyJwk);
    }

    private static TokenVerificationResult verifyCredentialJwt(OidcProvider provider, OidcTenantConfig oidcConfig,
            String credentialJwt) {
        try {
            final boolean enforceExpClaim = oidcConfig.token().age().isEmpty();
            return provider.verifyJwtToken(credentialJwt, false, false, null,
                    enforceExpClaim);
        } catch (InvalidJwtException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public static Set<String> extractCredentialIds(RoutingContext routingContext, VerifiableCredentialResolver resolver) {
        String queryParamCredentialId = resolver.getOidcvcConfig().queryParamCredentialId().orElse(null);

        if (queryParamCredentialId != null) {
            List<String> values = routingContext.queryParam(queryParamCredentialId);
            if (values != null) {
                return new HashSet<>(values);
            }
        }

        return Set.of();
    }

    public static boolean isTokenCredentialScopeAvailable(VerifiableCredentialResolver resolver, JsonObject jwt,
            String credentialId) {
        String jwtScope = jwt.getString("scope");
        if (jwtScope == null) {
            return false;
        }

        CredentialConfiguration credCfg = resolver.getMetadata().getCredentialConfigurations().get(credentialId);

        if (credCfg == null) {
            return false;
        }

        if (!jwtScope.contains(credCfg.scope())) {
            return false;
        }
        return true;
    }

}
