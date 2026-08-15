package io.quarkus.jwt.build;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.interfaces.RSAPublicKey;

import org.eclipse.microprofile.jwt.Claims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.quarkus.test.QuarkusExtensionTest;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.util.KeyUtils;

public class JwtBuildUnitTest {

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addAsResource("publicKey.pem")
                    .addAsResource("privateKey.pem")
                    .addAsResource("application.properties"));

    @Test
    public void signToken() throws Exception {
        String jwt = Jwt.preferredUserName("alice").sign();

        SignedJWT signedJWT = SignedJWT.parse(jwt);
        assertTrue(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) KeyUtils.readPublicKey("/publicKey.pem"))));
        JWTClaimsSet jwtClaims = signedJWT.getJWTClaimsSet();
        assertEquals("alice", jwtClaims.getStringClaim(Claims.preferred_username.name()));

    }
}
