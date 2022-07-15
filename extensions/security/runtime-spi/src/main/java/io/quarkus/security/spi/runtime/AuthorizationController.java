package io.quarkus.security.spi.runtime;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Singleton;

/**
 * controller that allows authorization to be disabled in tests.
 */
@Singleton
public class AuthorizationController {

    /**
     * Return a flag indicating if the authorization is required.
     *
     * @return the authorization requirement flag
     *
     * @deprecated Use
     */
    @Deprecated
    public boolean isAuthorizationEnabled() {
        return true;
    }

    /**
     * Return a flag indicating if the authorization is required.
     *
     * @param context the authorization context
     *
     * @return the authorization requirement flag
     */
    public boolean isAuthorizationEnabled(AuthorizationContext context) {
        return isAuthorizationEnabled();
    }

    public static class AuthorizationContext {
        private final String requestAddress;
        private final Map<String, Object> attributes;

        private AuthorizationContext(Builder builder) {
            this.requestAddress = builder.requestAddress;
            this.attributes = Collections.unmodifiableMap(builder.attributes);
        }

        public static Builder builder() {
            return new Builder();
        }

        public String getRequestAddress() {
            return requestAddress;
        }

        public Map<String, Object> getAttributes() {
            return attributes;
        }

        public static class Builder {

            String requestAddress;
            Map<String, Object> attributes = new HashMap<>();
            boolean built = false;

            public Builder setRequestAddress(String requestAddress) {
                if (built) {
                    throw new IllegalStateException();
                }
                this.requestAddress = requestAddress;
                return this;
            }

            public Builder addAttribute(String key, Object value) {
                if (built) {
                    throw new IllegalStateException();
                }
                attributes.put(key, value);
                return this;
            }

            public Builder addAttributes(Map<String, Object> attributes) {
                if (built) {
                    throw new IllegalStateException();
                }
                this.attributes.putAll(attributes);
                return this;
            }

            public AuthorizationContext build() {
                if (requestAddress == null) {
                    throw new IllegalStateException("Request address is null");
                }

                built = true;
                return new AuthorizationContext(this);
            }
        }
    }
}
