package io.quarkus.oidc.runtime;

import java.security.Key;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;

import io.quarkus.oidc.OIDCException;

public class JsonWebKeySet {

    private static final String RSA_KEY_TYPE = "RSA";
    private static final String ELLIPTIC_CURVE_KEY_TYPE = "EC";
    // This key type is used when EdDSA algorithm is used
    private static final String OCTET_KEY_PAIR_TYPE = "OKP";
    private static final Set<String> KEY_TYPES = Set.of(RSA_KEY_TYPE, ELLIPTIC_CURVE_KEY_TYPE, OCTET_KEY_PAIR_TYPE);

    private static final String SIGNATURE_USE = "sig";

    private Map<String, Key> keysWithKeyId = new HashMap<>();
    private Map<String, Key> keysWithThumbprints = new HashMap<>();
    private List<JsonWebKey> keysWithoutKeyIdAndThumbprint = new LinkedList<>();

    public JsonWebKeySet(String json) {
        initKeys(json);
    }

    private void initKeys(String json) {
        try {
            org.jose4j.jwk.JsonWebKeySet jwkSet = new org.jose4j.jwk.JsonWebKeySet(json);
            for (JsonWebKey jwkKey : jwkSet.getJsonWebKeys()) {
                if (isSupportedJwkKey(jwkKey)) {
                    if (jwkKey.getKeyId() != null) {
                        keysWithKeyId.put(jwkKey.getKeyId(), jwkKey.getKey());
                    }
                    // 'x5t' may not be available but the certificate `x5c` may be so 'x5t' can be calculated early
                    boolean calculateThumbprintIfMissing = true;
                    String x5t = ((PublicJsonWebKey) jwkKey).getX509CertificateSha1Thumbprint(calculateThumbprintIfMissing);
                    if (x5t != null && jwkKey.getKey() != null) {
                        keysWithThumbprints.put(x5t, jwkKey.getKey());
                    }
                    if (jwkKey.getKeyId() == null && x5t == null
                            && jwkKey.getKey() != null && KEY_TYPES.contains(jwkKey.getKeyType())
                            && SIGNATURE_USE.equals(jwkKey.getUse())) {
                        keysWithoutKeyIdAndThumbprint.add(jwkKey);
                    }
                }
            }

        } catch (JoseException ex) {
            throw new OIDCException(ex);
        }
    }

    private static boolean isSupportedJwkKey(JsonWebKey jwkKey) {
        return (jwkKey.getKeyType() == null || KEY_TYPES.contains(jwkKey.getKeyType()))
                && (SIGNATURE_USE.equals(jwkKey.getUse()) || jwkKey.getUse() == null);
    }

    public Key getKeyWithId(String kid) {
        return keysWithKeyId.get(kid);
    }

    public Key getKeyWithThumbprint(String x5t) {
        return keysWithThumbprints.get(x5t);
    }

    public Key getKeyWithoutKeyIdAndThumbprint(JsonWebSignature jws) {
        if (keysWithoutKeyIdAndThumbprint.isEmpty()) {
            return null;
        }
        try {
            String alg = jws.getAlgorithmHeaderValue();
            String keyType = jws.getKeyType();
            if (keyType == null || !KEY_TYPES.contains(keyType)) {
                return null;
            }
            for (int i = 0; i < keysWithoutKeyIdAndThumbprint.size(); i++) {
                JsonWebKey jwk = keysWithoutKeyIdAndThumbprint.get(i);
                if ((jwk.getAlgorithm() == null || jwk.getAlgorithm().equals(alg))
                        && jwk.getKeyType().equals(keyType)) {
                    return jwk.getKey();
                }
            }
            return null;
        } catch (InvalidAlgorithmException ex) {
            // May happen if jws.getKeyType() may not deduce the key type from the algorithm
            return null;
        }
    }
}
