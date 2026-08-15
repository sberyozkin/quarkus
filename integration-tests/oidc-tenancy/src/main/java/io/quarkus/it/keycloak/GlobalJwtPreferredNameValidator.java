package io.quarkus.it.keycloak;

import jakarta.enterprise.context.Dependent;

import io.quarkus.arc.Unremovable;
import io.smallrye.jwt.auth.ClaimsValidator;
import io.smallrye.jwt.common.JwtClaims;

@Unremovable
@Dependent
public class GlobalJwtPreferredNameValidator implements ClaimsValidator {

    @Override
    public String validate(VerificationContext context) {
        JwtClaims claims = context.claims();
        if (claims.containsKey("preferred_username")
                && claims.get("preferred_username") instanceof String
                && ((String) claims.get("preferred_username")).contains("jdoe")) {
            return "scope validation failed, the 'fail-validation' scope is not allowed";
        }
        return null;
    }
}
