package io.quarkus.oidc.common;

import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpRequest;

/**
 * Request filter which can be used to customize requests such as the verification JsonWebKey set and token grant requests
 * which are made from the OIDC adapter to the OIDC provider
 */
public interface OidcRequestFilter {

    enum Scope {
        ALL,
        /**
         * Applies to OIDC endpoint requests made by OIDC client, independently
         * of OIDC authorization code flow bearer token authentication mechanism
         * calls.
         */
        CLIENT,
        /**
         * Applies to OIDC endpoint requests made by OIDC authorization code flow
         * and bearer token authentication mechanisms
         */
        SERVER
    }

    enum Endpoint {
        ALL,

        /**
         * Applies to OIDC discovery requests
         */
        DISCOVERY,

        /**
         * Applies to OIDC token endpoint requests
         */
        TOKEN,

        /**
         * Applies to OIDC token revocation endpoint requests
         */
        TOKEN_REVOCATION,

        /**
         * Applies to OIDC token introspection requests
         */
        INTROSPECTION,
        /**
         * Applies to OIDC JSON Web Key Set endpoint requests
         */
        JWKS,
        /**
         * Applies to OIDC UserInfo endpoint requests
         */
        USERINFO
    }

    /**
     * Filter OIDC requests
     *
     * @param request HTTP request that can have its headers customized
     * @param body request body, will be null for HTTP GET methods, may be null for other HTTP methods
     * @param contextProperties context properties that can be available in context of some requests, can be null
     */
    void filter(HttpRequest<Buffer> request, Buffer requestBody, OidcRequestContextProperties contextProperties);

    default Scope scope() {
        return Scope.ALL;
    }

    default Endpoint endpoint() {
        return Endpoint.ALL;
    }
}
