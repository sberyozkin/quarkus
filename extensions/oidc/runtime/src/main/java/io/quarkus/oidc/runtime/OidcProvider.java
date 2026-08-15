package io.quarkus.oidc.runtime;

import static io.quarkus.oidc.common.runtime.OidcConstants.ACR;
import static io.quarkus.oidc.runtime.StepUpAuthenticationPolicy.throwAuthenticationFailedException;
import static java.util.Objects.requireNonNull;

import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logging.Logger;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.oidc.OIDCException;
import io.quarkus.oidc.OidcConfigurationMetadata;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TokenCustomizer;
import io.quarkus.oidc.TokenIntrospection;
import io.quarkus.oidc.UserInfo;
import io.quarkus.oidc.common.runtime.AbstractJsonObject;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.TokenCredential;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.ClaimsValidator;
import io.smallrye.jwt.auth.InvalidJWTException;
import io.smallrye.jwt.auth.JwtVerifier;
import io.smallrye.jwt.auth.TokenExpiredException;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.auth.VerificationKeyResolver;
import io.smallrye.jwt.common.JwtClaims;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.mutiny.Uni;

public class OidcProvider implements Closeable {

    private static final Logger LOG = Logger.getLogger(OidcProvider.class);
    private static final String ANY_AUDIENCE = "any";
    private static final String[] ASYMMETRIC_SUPPORTED_ALGORITHMS = new String[] { SignatureAlgorithm.RS256.getAlgorithm(),
            SignatureAlgorithm.RS384.getAlgorithm(),
            SignatureAlgorithm.RS512.getAlgorithm(),
            SignatureAlgorithm.ES256.getAlgorithm(),
            SignatureAlgorithm.ES384.getAlgorithm(),
            SignatureAlgorithm.ES512.getAlgorithm(),
            SignatureAlgorithm.PS256.getAlgorithm(),
            SignatureAlgorithm.PS384.getAlgorithm(),
            SignatureAlgorithm.PS512.getAlgorithm(),
            SignatureAlgorithm.EDDSA.getAlgorithm() };
    private static final Set<String> SYMMETRIC_ALLOWED_ALGORITHMS = Set.of(SignatureAlgorithm.HS256.getAlgorithm());
    static final Set<String> ASYMMETRIC_ALLOWED_ALGORITHMS = Set.of(ASYMMETRIC_SUPPORTED_ALGORITHMS);
    static final String ANY_ISSUER = "any";

    private final List<ClaimsValidator> customValidators;
    final OidcProviderClientImpl client;
    final RefreshableVerificationKeyResolver asymmetricKeyResolver;
    final DynamicVerificationKeyResolver keyResolverProvider;
    final OidcTenantConfig oidcConfig;
    final TokenCustomizer tokenCustomizer;
    final String issuer;
    final String[] audience;
    final Map<String, Set<String>> requiredClaims;
    final Set<String> requiredAllowedAlgorithms;

    public OidcProvider(OidcProviderClientImpl client, OidcTenantConfig oidcConfig, JsonWebKeySet jwks) {
        this(client, oidcConfig, jwks, TenantFeatureFinder.find(oidcConfig),
                TenantFeatureFinder.find(oidcConfig, ClaimsValidator.class));
    }

    public OidcProvider(OidcProviderClientImpl client, OidcTenantConfig oidcConfig, JsonWebKeySet jwks,
            TokenCustomizer tokenCustomizer, List<ClaimsValidator> customValidators) {
        this.client = client;
        this.oidcConfig = oidcConfig;
        this.tokenCustomizer = tokenCustomizer;
        if (jwks != null) {
            this.asymmetricKeyResolver = new JsonWebKeyResolver(jwks, oidcConfig.token().forcedJwkRefreshInterval());
        } else if (oidcConfig != null && oidcConfig.certificateChain().trustStoreFile().isPresent()) {
            this.asymmetricKeyResolver = new CertChainPublicKeyResolver(oidcConfig);
        } else {
            this.asymmetricKeyResolver = null;
        }

        if (client != null && oidcConfig != null && !oidcConfig.jwks().resolveEarly()) {
            this.keyResolverProvider = new DynamicVerificationKeyResolver(client, oidcConfig);
        } else {
            this.keyResolverProvider = null;
        }
        this.issuer = checkIssuerProp();
        this.audience = checkAudienceProp();
        this.requiredClaims = checkRequiredClaimsProp();
        this.requiredAllowedAlgorithms = checkSignatureAlgorithm();
        this.customValidators = customValidators == null ? List.of() : customValidators;
        if (client != null) {
            this.client.setOidcProvider(this);
        }
    }

    public OidcProvider(String publicKeyEnc, OidcTenantConfig oidcConfig) {
        this.client = null;
        this.oidcConfig = oidcConfig;
        this.tokenCustomizer = TenantFeatureFinder.find(oidcConfig);
        if (publicKeyEnc != null) {
            this.asymmetricKeyResolver = new LocalPublicKeyResolver(publicKeyEnc);
        } else if (oidcConfig.certificateChain().trustStoreFile().isPresent()) {
            this.asymmetricKeyResolver = new CertChainPublicKeyResolver(oidcConfig);
        } else {
            throw new IllegalStateException("Neither public key nor certificate chain verification modes are enabled");
        }
        this.keyResolverProvider = null;
        this.issuer = checkIssuerProp();
        this.audience = checkAudienceProp();
        this.requiredClaims = checkRequiredClaimsProp();
        this.requiredAllowedAlgorithms = checkSignatureAlgorithm();
        this.customValidators = TenantFeatureFinder.find(oidcConfig, ClaimsValidator.class);
    }

    private Set<String> checkSignatureAlgorithm() {
        if (oidcConfig != null && oidcConfig.token().signatureAlgorithm().isPresent()) {
            String configuredAlg = oidcConfig.token().signatureAlgorithm().get().getAlgorithm();
            return Set.of(configuredAlg);
        } else {
            return null;
        }
    }

    private String checkIssuerProp() {
        String issuerProp = null;
        if (oidcConfig != null) {
            issuerProp = oidcConfig.token().issuer().orElse(null);
            if (issuerProp == null && client != null) {
                issuerProp = client.getMetadata().getIssuer();
            }
        }
        return ANY_ISSUER.equals(issuerProp) ? null : issuerProp;
    }

    private String[] checkAudienceProp() {
        List<String> audienceProp = oidcConfig != null ? oidcConfig.token().audience().orElse(null) : null;
        return audienceProp != null ? audienceProp.toArray(new String[] {}) : null;
    }

    private Map<String, Set<String>> checkRequiredClaimsProp() {
        return oidcConfig != null && !oidcConfig.token().requiredClaims().isEmpty() ? oidcConfig.token().requiredClaims()
                : null;
    }

    public TokenVerificationResult verifySelfSignedJwtToken(String token, Key generatedInternalSignatureKey)
            throws Exception {
        return verifyJwtTokenInternal(token, true, false, null, SYMMETRIC_ALLOWED_ALGORITHMS,
                new InternalSignatureKeyResolver(generatedInternalSignatureKey),
                true, oidcConfig.token().issuedAtRequired());
    }

    public TokenVerificationResult verifyJwtToken(String token, boolean enforceAudienceVerification, boolean subjectRequired,
            String nonce)
            throws Exception {
        return verifyJwtTokenInternal(customizeJwtToken(token), enforceAudienceVerification, subjectRequired, nonce,
                (requiredAllowedAlgorithms != null ? requiredAllowedAlgorithms : ASYMMETRIC_ALLOWED_ALGORITHMS),
                asymmetricKeyResolver, true, oidcConfig.token().issuedAtRequired());
    }

    public TokenVerificationResult verifyJwtToken(String token, boolean enforceAudienceVerification, boolean subjectRequired,
            String nonce, boolean enforceExpReq)
            throws Exception {
        return verifyJwtTokenInternal(customizeJwtToken(token), enforceAudienceVerification, subjectRequired, nonce,
                (requiredAllowedAlgorithms != null ? requiredAllowedAlgorithms : ASYMMETRIC_ALLOWED_ALGORITHMS),
                asymmetricKeyResolver, enforceExpReq, oidcConfig.token().issuedAtRequired());
    }

    public TokenVerificationResult verifyLogoutJwtToken(String token) throws InvalidJWTException {
        final boolean enforceExpReq = !oidcConfig.token().age().isPresent();
        TokenVerificationResult result = verifyJwtTokenInternal(token, true, false, null, ASYMMETRIC_ALLOWED_ALGORITHMS,
                asymmetricKeyResolver, enforceExpReq, oidcConfig.token().issuedAtRequired());
        if (!enforceExpReq) {
            final Long exp = result.localVerificationResult().getLong(Claims.exp.name());
            if (exp != null) {
                final long secondsAfterExpiry = now() / 1000 - (exp + getLifespanGrace());
                if (secondsAfterExpiry > 0) {
                    String error = "Logout token issued to client %s expired %d seconds ago".formatted(
                            oidcConfig.clientId().get(),
                            secondsAfterExpiry);
                    LOG.warn(error);
                    throw new TokenExpiredException(error);
                }
            }
        }
        return result;
    }

    private TokenVerificationResult verifyJwtTokenInternal(String token,
            boolean enforceAudienceVerification,
            boolean subjectRequired,
            String nonce,
            Set<String> allowedAlgorithms,
            VerificationKeyResolver verificationKeyResolver, boolean enforceExpReq, boolean issuedAtRequired)
            throws InvalidJWTException {

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (java.text.ParseException ex) {
            throw new InvalidJWTException("Invalid JWT token format", ex);
        }

        JWSHeader header = signedJWT.getHeader();
        String alg = header.getAlgorithm().getName();

        if (!allowedAlgorithms.contains(alg)) {
            String detail = "Algorithm " + alg + " is not allowed";
            logVerificationFailure(detail);
            throw new InvalidJWTException(detail);
        }

        Key key;
        try {
            key = verificationKeyResolver.resolveKey(signedJWT);
        } catch (UnresolvableKeyException ex) {
            logVerificationFailure(ex.getMessage());
            throw new InvalidJWTException(ex.getMessage(), ex);
        }

        boolean signatureValid;
        try {
            JWSVerifier verifier = JwtVerifier.createVerifier(key, header.getAlgorithm());
            signatureValid = signedJWT.verify(verifier);
        } catch (JOSEException ex) {
            String detail = "Token signature verification failed";
            logVerificationFailure(detail);
            throw new InvalidJWTException(detail, ex);
        }
        if (!signatureValid) {
            String detail = "Token signature verification failed";
            logVerificationFailure(detail);
            throw new InvalidJWTException(detail);
        }

        JWTClaimsSet claimsSet;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (java.text.ParseException ex) {
            throw new InvalidJWTException("Invalid JWT token claims", ex);
        }
        JwtClaims claims = new JwtClaims(claimsSet.getClaims());

        if (enforceExpReq) {
            Long exp = claims.getExpirationTime();
            if (exp == null) {
                String detail = "No Expiration Time (exp) claim present";
                logVerificationFailure(detail);
                throw new InvalidJWTException(detail);
            }
            long nowSecs = now() / 1000;
            if (nowSecs > exp + getLifespanGrace()) {
                String detail = "Token has expired";
                logVerificationFailure(detail);
                throw new TokenExpiredException(detail);
            }
        }

        if (subjectRequired && claims.getSubject() == null) {
            String detail = "No Subject (sub) claim is present";
            logVerificationFailure(detail);
            throw new InvalidJWTException(detail);
        }

        if (issuedAtRequired && claims.getIssuedAt() == null) {
            String detail = "No IssuedAt (iat) claim present";
            logVerificationFailure(detail);
            throw new InvalidJWTException(detail);
        }

        if (issuer != null) {
            String tokenIssuer = claims.getIssuer();
            if (!issuer.equals(tokenIssuer)) {
                String detail = "Issuer (iss) claim value '" + tokenIssuer + "' does not match expected value of '" + issuer
                        + "'";
                logVerificationFailure(detail);
                throw new InvalidJWTException(detail);
            }
        }

        if (audience != null) {
            if (!(audience.length == 1 && audience[0].equals(ANY_AUDIENCE))) {
                List<String> tokenAudience = claims.getAudience();
                if (tokenAudience == null || tokenAudience.isEmpty()) {
                    String detail = "No Audience (aud) claim present";
                    logVerificationFailure(detail);
                    throw new InvalidJWTException(detail);
                }
                boolean found = false;
                for (String expectedAud : audience) {
                    if (tokenAudience.contains(expectedAud)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    String detail = "Audience (aud) claim " + tokenAudience + " does not contain expected value";
                    logVerificationFailure(detail);
                    throw new InvalidJWTException(detail);
                }
            }
        } else if (enforceAudienceVerification) {
            List<String> tokenAudience = claims.getAudience();
            String expectedAud = oidcConfig.clientId().get();
            if (tokenAudience == null || !tokenAudience.contains(expectedAud)) {
                String detail = "Audience (aud) claim " + tokenAudience + " does not contain expected value '" + expectedAud
                        + "'";
                logVerificationFailure(detail);
                throw new InvalidJWTException(detail);
            }
        }

        if (oidcConfig.token().lifespanGrace().isPresent()) {
            Long nbf = claims.getNotBefore();
            if (nbf != null) {
                long nowSecs = now() / 1000;
                int lifespanGrace = oidcConfig.token().lifespanGrace().getAsInt();
                if (nowSecs + lifespanGrace < nbf) {
                    String detail = "Token is not yet valid (nbf)";
                    logVerificationFailure(detail);
                    throw new InvalidJWTException(detail);
                }
            }
        }

        if (nonce != null) {
            Object tokenNonce = claims.get(OidcConstants.NONCE);
            if (tokenNonce == null || !nonce.equals(tokenNonce.toString())) {
                String detail = OidcConstants.NONCE + " claim value does not match the expected value";
                logVerificationFailure(detail);
                throw new InvalidJWTException(detail);
            }
        }

        final List<CatchingClaimsValidator> validators;
        if (!customValidators.isEmpty() || requiredClaims != null) {
            validators = new ArrayList<>();
            for (ClaimsValidator customValidator : customValidators) {
                validators.add(new CatchingClaimsValidator(customValidator));
            }
            if (requiredClaims != null) {
                validators.add(new CatchingClaimsValidator(new CustomClaimsValidator(requiredClaims)));
            }
            for (var validator : validators) {
                String error = validator.validate(claims);
                if (error != null) {
                    logVerificationFailure(error);
                    throw new InvalidJWTException(error);
                }
            }
        } else {
            validators = null;
        }

        if (validators != null) {
            for (CatchingClaimsValidator validator : validators) {
                if (validator.authenticationFailure != null) {
                    throw validator.authenticationFailure;
                }
            }
        }

        TokenVerificationResult result = new TokenVerificationResult(OidcCommonUtils.decodeJwtContent(token), null);

        verifyTokenAge(result.localVerificationResult().getLong(Claims.iat.name()));
        return result;
    }

    private void logVerificationFailure(String detail) {
        if (oidcConfig.clientId().isPresent()) {
            LOG.warnf("Verification of the token issued to client %s has failed: %s.", oidcConfig.clientId().get(),
                    detail);
            if (oidcConfig.clientName().isPresent()) {
                LOG.warnf(" Client name: %s", oidcConfig.clientName().get());
            }
        } else {
            LOG.warnf("Token verification has failed: %s", detail);
        }
    }

    static String getKeyTypeFromAlgorithm(String alg) {
        if (alg.startsWith("RS") || alg.startsWith("PS")) {
            return "RSA";
        }
        if (alg.startsWith("ES")) {
            return "EC";
        }
        if (alg.equals("EdDSA")) {
            return "OKP";
        }
        if (alg.startsWith("HS")) {
            return "oct";
        }
        return null;
    }

    private String customizeJwtToken(String token) {
        if (tokenCustomizer != null) {
            JsonObject headers = AbstractJsonObject.toJsonObject(
                    OidcUtils.decodeJwtHeadersAsString(token));
            headers = tokenCustomizer.customizeHeaders(headers);
            if (headers != null) {
                String newHeaders = new String(
                        Base64.getUrlEncoder().withoutPadding().encode(headers.toString().getBytes()),
                        StandardCharsets.UTF_8);
                int dotIndex = token.indexOf('.');
                String newToken = newHeaders + token.substring(dotIndex);
                return newToken;
            }
        }
        return token;
    }

    private void verifyTokenAge(Long iat) throws TokenExpiredException {
        if (oidcConfig.token().age().isPresent() && iat != null) {
            final long nowSecs = now() / 1000;

            if (nowSecs - iat > oidcConfig.token().age().get().toSeconds() + getLifespanGrace()) {
                final String errorMessage = "Token age exceeds the configured token age property";
                LOG.warn(errorMessage);
                throw new TokenExpiredException(errorMessage);
            }
        }
    }

    public Uni<TokenVerificationResult> refreshJwksAndVerifyJwtToken(String token, boolean enforceAudienceVerification,
            boolean subjectRequired, String nonce) {
        return asymmetricKeyResolver.refresh().onItem()
                .transformToUni(new Function<Void, Uni<? extends TokenVerificationResult>>() {

                    @Override
                    public Uni<? extends TokenVerificationResult> apply(Void v) {
                        try {
                            return Uni.createFrom()
                                    .item(verifyJwtToken(token, enforceAudienceVerification, subjectRequired, nonce));
                        } catch (Throwable t) {
                            return Uni.createFrom().failure(t);
                        }
                    }

                });
    }

    public Uni<TokenVerificationResult> getKeyResolverAndVerifyJwtToken(TokenCredential tokenCred,
            boolean enforceAudienceVerification,
            boolean subjectRequired, String nonce, boolean issuedAtRequired) {
        return keyResolverProvider.resolve(tokenCred).onItem()
                .transformToUni(new Function<VerificationKeyResolver, Uni<? extends TokenVerificationResult>>() {

                    @Override
                    public Uni<? extends TokenVerificationResult> apply(VerificationKeyResolver resolver) {
                        try {
                            return Uni.createFrom()
                                    .item(verifyJwtTokenInternal(customizeJwtToken(tokenCred.getToken()),
                                            enforceAudienceVerification,
                                            subjectRequired, nonce,
                                            (requiredAllowedAlgorithms != null ? requiredAllowedAlgorithms
                                                    : ASYMMETRIC_ALLOWED_ALGORITHMS),
                                            resolver, true, issuedAtRequired));
                        } catch (Throwable t) {
                            return Uni.createFrom().failure(t);
                        }
                    }

                });
    }

    public Uni<TokenIntrospection> introspectToken(String token, TokenType tokenType, Long expiresIn,
            boolean fallbackFromJwkMatch) {
        if (client.getMetadata().getIntrospectionUri() == null) {
            String errorMessage = String.format("Token issued to client %s "
                    + (fallbackFromJwkMatch ? "does not have a matching verification key and it " : "")
                    + "can not be introspected because the introspection endpoint address is unknown - "
                    + "please check if your OpenId Connect Provider supports the token introspection",
                    oidcConfig.clientId().get());

            throw new AuthenticationFailedException(errorMessage, tokenMap(token, tokenType));
        }
        return client.introspectAccessToken(token).onItemOrFailure()
                .transform(new BiFunction<TokenIntrospection, Throwable, TokenIntrospection>() {

                    @Override
                    public TokenIntrospection apply(TokenIntrospection introspectionResult, Throwable t) {
                        if (t != null) {
                            throw new AuthenticationFailedException(t, tokenMap(token, tokenType));
                        }
                        Long introspectionExpiresIn = introspectionResult.getLong(OidcConstants.INTROSPECTION_TOKEN_EXP);
                        if (introspectionExpiresIn == null && expiresIn != null) {
                            introspectionExpiresIn = now() + expiresIn;
                        }
                        if (!introspectionResult.isActive()) {
                            verifyTokenExpiry(token, tokenType, introspectionExpiresIn);
                            throw new AuthenticationFailedException(
                                    String.format("Token issued to client %s is not active", oidcConfig.clientId().get()),
                                    tokenMap(token, tokenType));
                        }
                        verifyTokenExpiry(token, tokenType, introspectionExpiresIn);
                        try {
                            verifyTokenAge(introspectionResult.getLong(OidcConstants.INTROSPECTION_TOKEN_IAT));
                        } catch (TokenExpiredException ex) {
                            throw new AuthenticationFailedException(ex, tokenMap(token, tokenType));
                        }

                        if (requiredClaims != null) {
                            for (Map.Entry<String, Set<String>> requiredClaim : requiredClaims.entrySet()) {
                                final String requiredClaimName = requiredClaim.getKey();
                                if (!introspectionResult.contains(requiredClaimName)) {
                                    LOG.debugf("Introspection claim %s is missing", requiredClaimName);
                                    throw new AuthenticationFailedException(tokenMap(token, tokenType));
                                }
                                final Set<String> requiredClaimValues = requiredClaim.getValue();
                                if (requiredClaimValues.size() == 1) {
                                    String introspectionClaimValue = null;
                                    try {
                                        introspectionClaimValue = introspectionResult.getString(requiredClaimName);
                                    } catch (ClassCastException ex) {
                                        LOG.debugf("Introspection claim %s is not String", requiredClaimName);
                                    }
                                    String requiredClaimValue = requiredClaimValues.iterator().next();
                                    if (requiredClaimValue.equals(introspectionClaimValue)) {
                                        continue;
                                    }
                                }
                                final JsonArray actualClaimValueArray;
                                try {
                                    actualClaimValueArray = requireNonNull(introspectionResult.getArray(requiredClaimName));
                                } catch (Exception ignored) {
                                    LOG.debugf("Introspection claim %s is neither string nor array", requiredClaimName);
                                    throw new AuthenticationFailedException(tokenMap(token, tokenType));
                                }
                                requiredClaimValuesLoop: for (String requiredClaimValue : requiredClaimValues) {
                                    for (int i = 0; i < actualClaimValueArray.size(); i++) {
                                        try {
                                            String actualClaimValue = actualClaimValueArray.getString(i);
                                            if (requiredClaimValue.equals(actualClaimValue)) {
                                                continue requiredClaimValuesLoop;
                                            }
                                        } catch (Exception ignored) {
                                            // try next actual claim value
                                        }
                                    }
                                    LOG.debugf("Value of the introspection claim %s does not match required value of %s",
                                            requiredClaimName, requiredClaimValue);
                                    throw new AuthenticationFailedException(tokenMap(token, tokenType));
                                }
                            }
                        }

                        return introspectionResult;
                    }

                });
    }

    private void verifyTokenExpiry(String token, TokenType tokenType, Long exp) {
        if (exp == null) {
            return;
        }
        final long secondsAfterExpiry = now() / 1000 - (exp + getLifespanGrace());
        if (secondsAfterExpiry > 0) {
            String error = "Token issued to client %s expired %d seconds ago".formatted(oidcConfig.clientId().get(),
                    secondsAfterExpiry);
            if (tokenType == TokenType.BEARER_ACCESS_TOKEN) {
                LOG.warn(error);
            } else {
                LOG.debug(error);
            }
            throw new AuthenticationFailedException(
                    new TokenExpiredException(error),
                    tokenMap(token, tokenType));
        }
    }

    private int getLifespanGrace() {
        return oidcConfig.token().lifespanGrace().isPresent()
                ? oidcConfig.token().lifespanGrace().getAsInt()
                : 0;
    }

    private static long now() {
        return System.currentTimeMillis();
    }

    public Uni<UserInfo> getUserInfo(String accessToken) {
        return client.getUserInfo(accessToken);
    }

    public Uni<AuthorizationCodeTokens> getCodeFlowTokens(String code, String redirectUri, String codeVerifier) {
        return client.getAuthorizationCodeTokens(code, redirectUri, codeVerifier);
    }

    public Uni<AuthorizationCodeTokens> refreshTokens(String refreshToken) {
        return client.refreshAuthorizationCodeTokens(refreshToken);
    }

    @Override
    public void close() {
        if (client != null) {
            client.close();
        }
    }

    private class JsonWebKeyResolver implements RefreshableVerificationKeyResolver {
        volatile JsonWebKeySet jwks;
        volatile long lastForcedRefreshTime;
        volatile long forcedJwksRefreshIntervalMilliSecs;
        final CertChainPublicKeyResolver chainResolverFallback;

        JsonWebKeyResolver(JsonWebKeySet jwks, Duration forcedJwksRefreshInterval) {
            this.jwks = jwks;
            this.forcedJwksRefreshIntervalMilliSecs = forcedJwksRefreshInterval.toMillis();
            if (oidcConfig.certificateChain().trustStoreFile().isPresent()) {
                chainResolverFallback = new CertChainPublicKeyResolver(oidcConfig);
            } else {
                chainResolverFallback = null;
            }
        }

        @Override
        public Key resolveKey(SignedJWT signedJWT) throws UnresolvableKeyException {
            Key key = null;

            JWSHeader header = signedJWT.getHeader();
            String kid = header.getKeyID();
            if (kid != null) {
                key = getKeyWithId(kid);
                if (key == null) {
                    throw new UnresolvableKeyException(String.format("JWK with kid '%s' is not available", kid));
                }
            }

            String thumbprint = null;
            if (key == null) {
                thumbprint = header.getX509CertSHA256Thumbprint() != null
                        ? header.getX509CertSHA256Thumbprint().toString()
                        : null;
                if (thumbprint != null) {
                    key = getKeyWithS256Thumbprint(thumbprint);
                    if (key == null) {
                        throw new UnresolvableKeyException(
                                String.format("JWK with the SHA256 certificate thumbprint '%s' is not available", thumbprint));
                    }
                }
            }

            if (key == null) {
                thumbprint = header.getX509CertThumbprint() != null ? header.getX509CertThumbprint().toString() : null;
                if (thumbprint != null) {
                    key = getKeyWithThumbprint(thumbprint);
                    if (key == null) {
                        throw new UnresolvableKeyException(
                                String.format("JWK with the certificate thumbprint '%s' is not available", thumbprint));
                    }
                }
            }

            if (key == null && kid == null && thumbprint == null) {
                try {
                    String keyType = getKeyTypeFromAlgorithm(header.getAlgorithm().getName());
                    key = jwks.getKeyWithoutKeyIdAndThumbprint(keyType);
                } catch (Exception ex) {
                    LOG.debug("Token 'alg'(algorithm) header value is invalid", ex);
                }
            }

            if (key == null && oidcConfig.jwks().tryAll() && kid == null && thumbprint == null) {
                LOG.debug("JWK is not available, neither 'kid' nor 'x5t#S256' nor 'x5t' token headers are set,"
                        + " falling back to trying all available keys");
                key = jwks.findKeyInAllKeys(signedJWT);
            }

            if (key == null && chainResolverFallback != null) {
                LOG.debug("JWK is not available, neither 'kid' nor 'x5t#S256' nor 'x5t' token headers are set,"
                        + " falling back to the certificate chain resolver");
                try {
                    key = chainResolverFallback.resolveKey(signedJWT);
                } catch (UnresolvableKeyException ex) {
                    throw ex;
                } catch (Exception ex) {
                    throw new UnresolvableKeyException("Certificate chain resolution failed", ex);
                }
            }

            if (key == null) {
                throw new UnresolvableKeyException(
                        "JWK is not available, neither 'kid' nor 'x5t#S256' nor 'x5t' token headers are set");
            } else {
                return key;
            }
        }

        private Key getKeyWithId(String kid) {
            if (kid != null) {
                return jwks.getKeyWithId(kid);
            } else {
                LOG.debug("Token 'kid' header is not set");
                return null;
            }
        }

        private Key getKeyWithThumbprint(String thumbprint) {
            if (thumbprint != null) {
                return jwks.getKeyWithThumbprint(thumbprint);
            } else {
                LOG.debug("Token 'x5t' header is not set");
                return null;
            }
        }

        private Key getKeyWithS256Thumbprint(String thumbprint) {
            if (thumbprint != null) {
                return jwks.getKeyWithS256Thumbprint(thumbprint);
            } else {
                LOG.debug("Token 'x5tS256' header is not set");
                return null;
            }
        }

        public Uni<Void> refresh() {
            final long now = now();
            if (now > lastForcedRefreshTime + forcedJwksRefreshIntervalMilliSecs) {
                lastForcedRefreshTime = now;
                return client.getJsonWebKeySet(null).onItem()
                        .transformToUni(new Function<JsonWebKeySet, Uni<? extends Void>>() {

                            @Override
                            public Uni<? extends Void> apply(JsonWebKeySet t) {
                                jwks = t;
                                return Uni.createFrom().voidItem();
                            }

                        });
            } else {
                return Uni.createFrom().voidItem();
            }
        }

    }

    private static class LocalPublicKeyResolver implements RefreshableVerificationKeyResolver {
        Key key;

        LocalPublicKeyResolver(String publicKeyEnc) {
            try {
                key = KeyUtils.decodePublicKey(publicKeyEnc);
            } catch (Exception ex) {
                throw new OIDCException(ex);
            }
        }

        @Override
        public Key resolveKey(SignedJWT signedJWT) throws UnresolvableKeyException {
            return key;
        }

    }

    private class InternalSignatureKeyResolver implements VerificationKeyResolver {
        final Key internalSignatureKey;

        public InternalSignatureKeyResolver(Key generatedInternalSignatureKey) {
            this.internalSignatureKey = initKey(generatedInternalSignatureKey);
        }

        @Override
        public Key resolveKey(SignedJWT signedJWT) throws UnresolvableKeyException {
            return internalSignatureKey;
        }

        private Key initKey(Key generatedInternalSignatureKey) {
            String clientSecret = client.getClientSecret();
            if (clientSecret != null) {
                LOG.debug("Verifying internal ID token with a configured client secret");
                return KeyUtils.createSecretKeyFromSecret(clientSecret);
            } else if (client.getClientJwtKey() instanceof PrivateKey) {
                LOG.debug("Verifying internal ID token with a configured JWT private key");
                return OidcUtils.createSecretKeyFromDigest(((PrivateKey) client.getClientJwtKey()).getEncoded());
            } else {
                LOG.debug("Verifying internal ID token with a generated secret key");
                return generatedInternalSignatureKey;
            }
        }
    }

    public OidcConfigurationMetadata getMetadata() {
        return client == null ? null : client.getMetadata();
    }

    private static final class CustomClaimsValidator implements ClaimsValidator {

        private final Map<String, Set<String>> customClaims;

        private CustomClaimsValidator(Map<String, Set<String>> customClaims) {
            this.customClaims = customClaims;
        }

        @Override
        public String validate(VerificationContext context) {
            JwtClaims claims = context.claims();
            for (var requiredClaim : customClaims.entrySet()) {
                String validationFailureMessage = validateClaim(requiredClaim.getKey(), requiredClaim.getValue(), claims);
                if (validationFailureMessage != null) {
                    if (ACR.equals(requiredClaim.getKey())) {
                        throwAuthenticationFailedException(validationFailureMessage, requiredClaim.getValue());
                    }
                    return validationFailureMessage;
                }
            }
            return null;
        }

        @SuppressWarnings("unchecked")
        private static String validateClaim(String requiredClaimName, Set<String> requiredClaimValues, JwtClaims claims) {
            if (!claims.containsKey(requiredClaimName)) {
                return "claim " + requiredClaimName + " is missing";
            }
            Object claimValue = claims.get(requiredClaimName);
            if (claimValue instanceof String) {
                if (requiredClaimValues.size() == 1) {
                    String actualClaimValue = (String) claimValue;
                    String requiredClaimValue = requiredClaimValues.iterator().next();
                    if (!requiredClaimValue.equals(actualClaimValue)) {
                        return "claim " + requiredClaimName + " does not match expected value of " + requiredClaimValues;
                    }
                } else {
                    return "expected claim " + requiredClaimName + " must be a list of strings";
                }
            } else if (claimValue instanceof List) {
                List<String> actualClaimValues = (List<String>) claimValue;
                for (String requiredClaimValue : requiredClaimValues) {
                    if (!actualClaimValues.contains(requiredClaimValue)) {
                        return "claim " + requiredClaimName + " does not match expected value of " + requiredClaimValues;
                    }
                }
            } else {
                return "expected claim " + requiredClaimName + " must be a list of strings or a string";
            }
            return null;
        }
    }

    private static Map<String, Object> tokenMap(String token, TokenType tokenType) {
        return Map.of(tokenType == TokenType.ID_TOKEN ? OidcConstants.ID_TOKEN_VALUE : OidcConstants.ACCESS_TOKEN_VALUE,
                token);
    }

    private static final class CatchingClaimsValidator {

        private AuthenticationFailedException authenticationFailure;
        private final ClaimsValidator validator;

        private CatchingClaimsValidator(ClaimsValidator validator) {
            this.validator = validator;
        }

        String validate(JwtClaims claims) {
            try {
                return validator.validate(new ClaimsValidator.VerificationContext(claims));
            } catch (AuthenticationFailedException e) {
                if (e.getAttribute(OidcConstants.ACR_VALUES) != null) {
                    authenticationFailure = e;
                    return null;
                } else {
                    throw e;
                }
            }
        }
    }

    public static boolean isTokenExpired(Throwable t) {
        if (t == null) {
            return false;
        }
        return t instanceof TokenExpiredException || t.getCause() instanceof TokenExpiredException;
    }
}
