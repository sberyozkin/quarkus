package io.quarkus.jwt.test;

import static org.hamcrest.Matchers.equalTo;

import java.security.PrivateKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

import io.quarkus.test.QuarkusExtensionTest;
import io.restassured.RestAssured;
import io.smallrye.jwt.util.KeyUtils;

public class JwtParserUnitTest {
    private static Class<?>[] testClasses = {
            JwtParserEndpoint.class
    };

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(testClasses)
                    .addAsResource("publicKey.pem")
                    .addAsResource("privateKey.pem")
                    .addAsResource("applicationJwtParser.properties", "application.properties"));

    @Test
    public void verifyTokenWithoutIssuedAt() throws Exception {
        RestAssured.given().auth()
                .oauth2(generateTokenWithoutIssuedAt())
                .get("/parser/name")
                .then().assertThat().statusCode(200)
                .body(equalTo("alice"));
    }

    @Test
    public void verifyTokenWithoutIssuedAtWithKey() throws Exception {
        RestAssured.given().auth()
                .oauth2(generateTokenWithoutIssuedAt())
                .get("/parser/name-with-key")
                .then().assertThat().statusCode(200)
                .body(equalTo("alice"));
    }

    private String generateTokenWithoutIssuedAt() throws Exception {
        String payload = "{"
                + "\"sub\":\"alice\","
                + "\"iss\":\"https://server.example.com\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + 5) + ","
                + "}";

        PrivateKey privateKey = KeyUtils.readPrivateKey("privateKey.pem");
        JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload(payload));
        jws.sign(new RSASSASigner(privateKey));
        return jws.serialize();
    }
}
