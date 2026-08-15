package io.quarkus.oidc.runtime;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.logging.Logger;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;

import io.quarkus.oidc.OIDCException;
import io.smallrye.jwt.auth.JwtVerifier;

public class JsonWebKeySet {

    private static final Logger LOG = Logger.getLogger(JsonWebKeySet.class);
    private static final String RSA_KEY_TYPE = KeyType.RSA.getValue();
    private static final String ELLIPTIC_CURVE_KEY_TYPE = KeyType.EC.getValue();
    private static final String OCTET_KEY_PAIR_TYPE = KeyType.OKP.getValue();
    private static final String OCTET_SEQUENCE_KEY_TYPE = KeyType.OCT.getValue();
    private static final Set<String> KEY_TYPES = Set.of(RSA_KEY_TYPE, ELLIPTIC_CURVE_KEY_TYPE, OCTET_KEY_PAIR_TYPE);

    private static final String SIGNATURE_USE = "sig";

    private Map<String, Key> keysWithKeyId = new HashMap<>();
    private Map<String, Key> keysWithThumbprints = new HashMap<>();
    private Map<String, Key> keysWithS256Thumbprints = new HashMap<>();
    private Map<String, List<Key>> keysWithoutKeyIdAndThumbprint = new HashMap<>();
    private Map<String, List<Key>> allKeys = new HashMap<>();

    public JsonWebKeySet(String json) {
        initKeys(json);
    }

    private void initKeys(String json) {
        try {
            JWKSet jwkSet = JWKSet.parse(json);
            for (JWK jwkKey : jwkSet.getKeys()) {
                if (isSupportedJwkKey(jwkKey)) {
                    Key key;
                    try {
                        key = extractKey(jwkKey);
                    } catch (JOSEException ex) {
                        logKeyExtractionFailure(jwkKey, ex);
                        continue;
                    }
                    final String keyType = jwkKey.getKeyType() != null ? jwkKey.getKeyType().getValue() : null;

                    addKeyToListInMap(keyType, key, allKeys);

                    if (jwkKey.getKeyID() != null) {
                        keysWithKeyId.put(jwkKey.getKeyID(), key);
                    }

                    Base64URL x5tBase64 = jwkKey.getX509CertThumbprint();
                    String x5t = x5tBase64 != null ? x5tBase64.toString() : null;

                    Base64URL x5tS256Base64 = jwkKey.getX509CertSHA256Thumbprint();
                    String x5tS256 = x5tS256Base64 != null ? x5tS256Base64.toString() : null;

                    // Fall back to computing any missing thumbprint from the already parsed leaf certificate
                    if (x5t == null || x5tS256 == null) {
                        List<X509Certificate> certChain = jwkKey.getParsedX509CertChain();
                        if (certChain != null && !certChain.isEmpty()) {
                            X509Certificate leafCert = certChain.get(0);
                            if (x5t == null) {
                                x5t = X509CertUtils.computeSHA1Thumbprint(leafCert).toString();
                            }
                            if (x5tS256 == null) {
                                x5tS256 = X509CertUtils.computeSHA256Thumbprint(leafCert).toString();
                            }
                        }
                    }

                    if (x5t != null) {
                        keysWithThumbprints.put(x5t, key);
                    }
                    if (x5tS256 != null) {
                        keysWithS256Thumbprints.put(x5tS256, key);
                    }

                    if (jwkKey.getKeyID() == null && x5t == null && x5tS256 == null && keyType != null) {
                        addKeyToListInMap(keyType, key, keysWithoutKeyIdAndThumbprint);
                    }
                }
            }
        } catch (ParseException ex) {
            throw new OIDCException(ex);
        }
    }

    private static Key extractKey(JWK jwkKey) throws JOSEException {
        if (jwkKey instanceof AsymmetricJWK) {
            return ((AsymmetricJWK) jwkKey).toPublicKey();
        } else if (jwkKey instanceof OctetSequenceKey) {
            return ((OctetSequenceKey) jwkKey).toSecretKey();
        }
        return null;
    }

    private static void logKeyExtractionFailure(JWK jwkKey, JOSEException ex) {
        String keyType = jwkKey.getKeyType() != null ? jwkKey.getKeyType().getValue() : null;
        LOG.warnf(ex, "Supported JWK of type '%s' with key id '%s' can not be converted to a key and will be ignored",
                keyType, jwkKey.getKeyID());
    }

    private static boolean isSupportedJwkKey(JWK jwkKey) {
        String keyType = jwkKey.getKeyType() != null ? jwkKey.getKeyType().getValue() : null;
        String use = jwkKey.getKeyUse() != null ? jwkKey.getKeyUse().getValue() : null;
        return (keyType == null || KEY_TYPES.contains(keyType))
                && (SIGNATURE_USE.equals(use) || use == null);
    }

    private void addKeyToListInMap(String keyType, Key key, Map<String, List<Key>> map) {
        List<Key> keys = map.get(keyType);

        if (keys == null) {
            keys = new ArrayList<>();
            map.put(keyType, keys);
        }

        keys.add(key);
    }

    public Key findKeyInAllKeys(SignedJWT signedJWT) {
        LOG.debug("Evaluating all keys to find a matching one");

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        String keyType = getKeyTypeFromAlgorithm(alg);
        if (keyType == null) {
            LOG.debug("No key type available, cannot determine keys to check");
            return null;
        }

        for (Key key : allKeys.getOrDefault(keyType, List.of())) {
            try {
                JWSVerifier verifier = JwtVerifier.createVerifier(key, signedJWT.getHeader().getAlgorithm());
                if (signedJWT.verify(verifier)) {
                    LOG.debugf("Found matching key %s", key.toString());
                    return key;
                }
            } catch (JOSEException e) {
                LOG.debugf(e, "Verifying signature with key %s failed.", key.toString());
            }
        }

        LOG.debug("No matching key found");
        return null;
    }

    static String getKeyTypeFromAlgorithm(String alg) {
        if (alg.startsWith("RS") || alg.startsWith("PS")) {
            return RSA_KEY_TYPE;
        }
        if (alg.startsWith("ES")) {
            return ELLIPTIC_CURVE_KEY_TYPE;
        }
        if (alg.equals("EdDSA")) {
            return OCTET_KEY_PAIR_TYPE;
        }
        if (alg.startsWith("HS")) {
            return OCTET_SEQUENCE_KEY_TYPE;
        }
        return null;
    }

    public Key getKeyWithId(String kid) {
        return keysWithKeyId.get(kid);
    }

    public Key getKeyWithThumbprint(String x5t) {
        return keysWithThumbprints.get(x5t);
    }

    public Key getKeyWithS256Thumbprint(String x5tS256) {
        return keysWithS256Thumbprints.get(x5tS256);
    }

    public Key getKeyWithoutKeyIdAndThumbprint(String keyType) {
        List<Key> keys = keysWithoutKeyIdAndThumbprint.get(keyType);
        return keys == null || keys.size() != 1 ? null : keys.get(0);
    }
}
