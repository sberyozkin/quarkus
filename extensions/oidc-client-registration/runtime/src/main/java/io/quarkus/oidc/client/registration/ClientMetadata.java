package io.quarkus.oidc.client.registration;

import java.util.List;

import io.quarkus.oidc.common.runtime.OidcConstants;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

public class ClientMetadata {

    JsonObject json;

    public ClientMetadata() {
        this(new JsonObject());
    }

    public ClientMetadata(String json) {
        this(new JsonObject(json));
    }

    public ClientMetadata(JsonObject json) {
        this.json = json;
    }

    public String getClientId() {
        return json.getString(OidcConstants.CLIENT_ID);
    }

    public String getClientSecret() {
        return json.getString(OidcConstants.CLIENT_SECRET);
    }

    public List<String> getRedirectUris() {
        return getList(OidcConstants.CLIENT_METADATA_REDIRECT_URIS);
    }

    public List<String> getPostLogoutUris() {
        return getList(OidcConstants.CLIENT_METADATA_POST_LOGOUT_URIS);
    }

    public String getString(String name) {
        return json.getString(name);
    }

    public String toString() {
        return json.toString();
    }

    private List<String> getList(String prop) {
        JsonArray array = json.getJsonArray(prop);
        if (array == null) {
            return null;
        }
        @SuppressWarnings("unchecked")
        List<String> listOfStrings = (List<String>) array.getList();
        return listOfStrings;
    }
}
