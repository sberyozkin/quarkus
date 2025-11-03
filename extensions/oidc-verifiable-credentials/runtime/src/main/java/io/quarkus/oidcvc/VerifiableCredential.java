package io.quarkus.oidcvc;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.authlete.sd.SDJWT;

import io.quarkus.oidc.runtime.OidcUtils;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

public class VerifiableCredential {

    final private String credentialId;
    final private SDJWT sdJwt;
    final private String keyBindingPrivateKey;

    public VerifiableCredential() {
        this(null, null, null);
    }

    public VerifiableCredential(String credentialId, String sdJwt, String keyBindingPrivateKey) {
        this.credentialId = credentialId;
        this.sdJwt = SDJWT.parse(sdJwt);
        this.keyBindingPrivateKey = keyBindingPrivateKey;
    }

    public String getCredentialJwt() {
        return sdJwt.getCredentialJwt();
    }

    public List<Disclosure> getDisclosures() {

        JsonObject jwt = OidcUtils.decodeJwtContent(sdJwt.getCredentialJwt());
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

        return verifiedDisclosures;
    }

    public String getSdJwt() {
        return sdJwt.toString();
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getKeyBindingPrivateKey() {
        return keyBindingPrivateKey;
    }

    public static record Disclosure(String name, Object value) {
    }
}
