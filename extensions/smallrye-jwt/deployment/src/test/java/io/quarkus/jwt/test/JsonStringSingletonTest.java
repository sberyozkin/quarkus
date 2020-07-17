package io.quarkus.jwt.test;

import static org.hamcrest.Matchers.equalTo;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import io.smallrye.jwt.build.Jwt;

public class JsonStringSingletonTest {
    private static Class<?>[] testClasses = {
            JsonStringSingletonEndpoint.class,
    };

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClasses(testClasses)
                    .addAsResource("publicKey.pem")
                    .addAsResource("privateKey.pem")
                    .addAsResource("application.properties"));

    @Test
    public void verifyUpnClaim() throws Exception {
        String token1 = generateToken("alice");
        RestAssured.given().auth()
                .oauth2(token1)
                .when().get("/endp/upns")
                .then()
                .statusCode(200).body(equalTo("alice"));
        String token2 = generateToken("bob");
        RestAssured.given().auth()
                .oauth2(token2)
                .when().get("/endp/upns")
                .then()
                .statusCode(200).body(equalTo("bob"));
    }

    private String generateToken(String upn) {
        return Jwt.upn(upn).sign();
    }
}
