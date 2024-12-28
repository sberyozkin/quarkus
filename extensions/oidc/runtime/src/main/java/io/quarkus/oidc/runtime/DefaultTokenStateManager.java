package io.quarkus.oidc.runtime;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TokenStateManager;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.runtime.OidcTenantConfig.TokenStateManager.Strategy;
import io.quarkus.security.AuthenticationCompletionException;
import io.quarkus.security.AuthenticationFailedException;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.mutiny.Uni;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.impl.ServerCookie;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

@ApplicationScoped
public class DefaultTokenStateManager implements TokenStateManager {

    private static final String ID_TOKEN = "id";
    private static final String ACCESS_TOKEN = "at";
    private static final String REFRESH_TOKEN = "rt";

    @Override
    public Uni<String> createTokenState(RoutingContext routingContext, OidcTenantConfig oidcConfig,
            AuthorizationCodeTokens tokens, OidcRequestContext<String> requestContext) {

        if (!oidcConfig.tokenStateManager().splitTokens()) {
            // ID, access and refresh tokens are all represented by a single cookie.
            // In this case they are all encrypted once all tokens have been added to the buffer.

            JsonObject json = new JsonObject();

            // Add ID token
            json.put(ID_TOKEN, tokens.getIdToken());

            // By default, all three tokens are retained
            if (oidcConfig.tokenStateManager().strategy() == Strategy.KEEP_ALL_TOKENS) {
                // Add access and refresh tokens
                json.put(ACCESS_TOKEN, tokens.getAccessToken())
                        .put(REFRESH_TOKEN, tokens.getRefreshToken());
            } else if (oidcConfig.tokenStateManager().strategy() == Strategy.ID_REFRESH_TOKENS) {
                // But sometimes the access token is not required.
                // For example, when the Quarkus endpoint does not need to use it to access another service.
                // Skip access token, add refresh token
                json.put(REFRESH_TOKEN, tokens.getRefreshToken());
            }

            // Now all three tokens are encrypted
            String encryptedTokens = encryptJson(json, routingContext, oidcConfig);
            return Uni.createFrom().item(encryptedTokens);
        } else {
            // ID, access and refresh tokens are represented as individual cookies

            // Encrypt ID token
            String encryptedIdToken = encryptJson(jsonIdToken(tokens.getIdToken()), routingContext, oidcConfig);

            // By default, all three tokens are retained
            if (oidcConfig.tokenStateManager().strategy() == Strategy.KEEP_ALL_TOKENS) {

                // Encrypt access token and create a `q_session_at` cookie.
                CodeAuthenticationMechanism.createCookie(routingContext,
                        oidcConfig,
                        getAccessTokenCookieName(oidcConfig),
                        encryptJson(jsonAccessToken(tokens.getAccessToken()), routingContext, oidcConfig),
                        routingContext.get(CodeAuthenticationMechanism.SESSION_MAX_AGE_PARAM), true);

                // Encrypt refresh token and create a `q_session_rt` cookie.
                if (tokens.getRefreshToken() != null) {
                    CodeAuthenticationMechanism.createCookie(routingContext,
                            oidcConfig,
                            getRefreshTokenCookieName(oidcConfig),
                            encryptJson(jsonRefrehToken(tokens.getRefreshToken()), routingContext, oidcConfig),
                            routingContext.get(CodeAuthenticationMechanism.SESSION_MAX_AGE_PARAM), true);
                }
            } else if (oidcConfig.tokenStateManager().strategy() == Strategy.ID_REFRESH_TOKENS
                    && tokens.getRefreshToken() != null) {
                // Encrypt refresh token and create a `q_session_rt` cookie.
                CodeAuthenticationMechanism.createCookie(routingContext,
                        oidcConfig,
                        getRefreshTokenCookieName(oidcConfig),
                        encryptJson(jsonRefrehToken(tokens.getRefreshToken()), routingContext, oidcConfig),
                        routingContext.get(CodeAuthenticationMechanism.SESSION_MAX_AGE_PARAM));
            }

            // q_session cookie
            return Uni.createFrom().item(encryptedIdToken);
        }

    }

    @Override
    public Uni<AuthorizationCodeTokens> getTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState,
            OidcRequestContext<AuthorizationCodeTokens> requestContext) {

        String idToken = null;
        String accessToken = null;
        String refreshToken = null;

        try {
            if (!oidcConfig.tokenStateManager().splitTokens()) {
                // ID, access and refresh tokens are all be represented by a single cookie.

                JsonObject json = decryptJson(tokenState, routingContext, oidcConfig);
                idToken = json.getString(ID_TOKEN);
                accessToken = null;
                refreshToken = null;

                if (oidcConfig.tokenStateManager().strategy() == Strategy.KEEP_ALL_TOKENS) {
                    accessToken = json.getString(ACCESS_TOKEN);
                    refreshToken = json.getString(REFRESH_TOKEN);
                } else if (oidcConfig.tokenStateManager().strategy() == Strategy.ID_REFRESH_TOKENS) {
                    refreshToken = json.getString(REFRESH_TOKEN);
                }

            } else {
                // Decrypt ID token from the q_session cookie
                idToken = decryptJsonIdToken(tokenState, routingContext, oidcConfig);
                accessToken = null;
                refreshToken = null;

                if (oidcConfig.tokenStateManager().strategy() == Strategy.KEEP_ALL_TOKENS) {
                    Cookie atCookie = getAccessTokenCookie(routingContext, oidcConfig);
                    if (atCookie != null) {
                        // Decrypt access token from the q_session_at cookie
                        accessToken = decryptJsonAccessToken(atCookie.getValue(), routingContext, oidcConfig);
                    }
                    Cookie rtCookie = getRefreshTokenCookie(routingContext, oidcConfig);
                    if (rtCookie != null) {
                        // Decrypt refresh token from the q_session_rt cookie
                        refreshToken = decryptJsonRefreshToken(rtCookie.getValue(), routingContext, oidcConfig);
                    }
                } else if (oidcConfig.tokenStateManager().strategy() == Strategy.ID_REFRESH_TOKENS) {
                    Cookie rtCookie = getRefreshTokenCookie(routingContext, oidcConfig);
                    if (rtCookie != null) {
                        refreshToken = decryptJsonRefreshToken(rtCookie.getValue(), routingContext, oidcConfig);
                    }
                }
            }
        } catch (Exception ex) {
            return Uni.createFrom().failure(new AuthenticationCompletionException("Session cookie is malformed"));
        }
        return Uni.createFrom().item(new AuthorizationCodeTokens(idToken, accessToken, refreshToken));
    }

    @Override
    public Uni<Void> deleteTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState,
            OidcRequestContext<Void> requestContext) {
        if (oidcConfig.tokenStateManager().splitTokens()) {
            OidcUtils.removeCookie(routingContext, getAccessTokenCookie(routingContext, oidcConfig),
                    oidcConfig);
            OidcUtils.removeCookie(routingContext, getRefreshTokenCookie(routingContext, oidcConfig),
                    oidcConfig);
        }
        return CodeAuthenticationMechanism.VOID_UNI;
    }

    private static ServerCookie getAccessTokenCookie(RoutingContext routingContext, OidcTenantConfig oidcConfig) {
        return (ServerCookie) routingContext.request().getCookie(getAccessTokenCookieName(oidcConfig));
    }

    private static ServerCookie getRefreshTokenCookie(RoutingContext routingContext, OidcTenantConfig oidcConfig) {
        return (ServerCookie) routingContext.request().getCookie(getRefreshTokenCookieName(oidcConfig));
    }

    private static String getAccessTokenCookieName(OidcTenantConfig oidcConfig) {
        String cookieSuffix = OidcUtils.getCookieSuffix(oidcConfig);
        return OidcUtils.SESSION_AT_COOKIE_NAME + cookieSuffix;
    }

    private static String getRefreshTokenCookieName(OidcTenantConfig oidcConfig) {
        String cookieSuffix = OidcUtils.getCookieSuffix(oidcConfig);
        return OidcUtils.SESSION_RT_COOKIE_NAME + cookieSuffix;
    }

    private String encryptJson(JsonObject json, RoutingContext context, OidcTenantConfig oidcConfig) {
        String jsonString = json.toString();
        String data = oidcConfig.tokenStateManager().encryptionRequired() ? jsonString
                : Base64.getUrlEncoder().withoutPadding().encodeToString(jsonString.getBytes(StandardCharsets.UTF_8));
        return encryptToken(data, context, oidcConfig);
    }

    private String encryptToken(String token, RoutingContext context, OidcTenantConfig oidcConfig) {
        if (oidcConfig.tokenStateManager().encryptionRequired()) {
            TenantConfigContext configContext = context.get(TenantConfigContext.class.getName());
            try {
                KeyEncryptionAlgorithm encAlgorithm = KeyEncryptionAlgorithm
                        .valueOf(oidcConfig.tokenStateManager().encryptionAlgorithm().name());
                return OidcUtils.encryptString(token, configContext.getTokenEncSecretKey(), encAlgorithm);
            } catch (Exception ex) {
                throw new AuthenticationFailedException(ex);
            }
        }
        return token;
    }

    private JsonObject jsonRefrehToken(String refreshToken) {
        return new JsonObject().put(REFRESH_TOKEN, refreshToken);
    }

    private JsonObject jsonAccessToken(String accessToken) {
        return new JsonObject().put(ACCESS_TOKEN, accessToken);
    }

    private JsonObject jsonIdToken(String idToken) {
        return new JsonObject().put(ID_TOKEN, idToken);
    }

    private String decryptToken(String token, RoutingContext context, OidcTenantConfig oidcConfig) {
        if (oidcConfig.tokenStateManager().encryptionRequired()) {
            TenantConfigContext configContext = context.get(TenantConfigContext.class.getName());
            try {
                KeyEncryptionAlgorithm encAlgorithm = KeyEncryptionAlgorithm
                        .valueOf(oidcConfig.tokenStateManager().encryptionAlgorithm().name());
                return OidcUtils.decryptString(token, configContext.getTokenEncSecretKey(), encAlgorithm);
            } catch (Exception ex) {
                throw new AuthenticationFailedException(ex);
            }
        }
        return token;
    }

    private JsonObject decryptJson(String token, RoutingContext context, OidcTenantConfig oidcConfig) {
        String json = decryptToken(token, context, oidcConfig);
        if (!oidcConfig.tokenStateManager().encryptionRequired()) {
            json = OidcCommonUtils.base64UrlDecode(json);
        }
        return new JsonObject(json);
    }

    private String decryptJsonIdToken(String token, RoutingContext context, OidcTenantConfig oidcConfig) {
        JsonObject json = decryptJson(token, context, oidcConfig);
        return json.getString(ID_TOKEN);
    }

    private String decryptJsonAccessToken(String token, RoutingContext context, OidcTenantConfig oidcConfig) {
        JsonObject json = decryptJson(token, context, oidcConfig);
        return json.getString(ACCESS_TOKEN);
    }

    private String decryptJsonRefreshToken(String token, RoutingContext context, OidcTenantConfig oidcConfig) {
        JsonObject json = decryptJson(token, context, oidcConfig);
        return json.getString(REFRESH_TOKEN);
    }
}
