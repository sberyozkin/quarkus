package io.quarkus.tls.runtime;

import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.function.Consumer;
import java.util.function.Supplier;

import jakarta.enterprise.event.Event;
import jakarta.enterprise.inject.spi.CDI;

import org.jboss.logging.Logger;

import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.tls.CertificateUpdatedEvent;
import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.quarkus.tls.runtime.config.TlsConfig;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;

/**
 * Recorder for Let's Encrypt support.
 */
@Recorder
public class LetsEncryptRecorder {

    private TlsConfigurationRegistry registry;
    private Event<CertificateUpdatedEvent> event;
    volatile Buffer challenge;
    private static final Logger LOGGER = Logger.getLogger(LetsEncryptRecorder.class);

    public void initialize(Supplier<TlsConfigurationRegistry> registry) {
        this.registry = registry.get();
        this.event = CDI.current().getBeanManager().getEvent().select(CertificateUpdatedEvent.class);
    }

    /**
     * Returns a handler that serves the Let's Encrypt challenge.
     *
     * @return the handler that serves the Let's Encrypt challenge, returns a 404 status code if the challenge is not set.
     */
    public Handler<RoutingContext> challengeHandler() {
        return new Handler<RoutingContext>() {
            @Override
            public void handle(RoutingContext rc) {
                if (rc.request().method() != HttpMethod.GET) {
                    rc.response().setStatusCode(405).end();
                    return;
                }
                if (challenge == null) {
                    LOGGER.debug("No Let's Encrypt challenge has been set");
                    rc.response().setStatusCode(404).end();
                } else {
                    rc.response().end(challenge);
                }
            }
        };
    }

    /**
     * Cleans up the ACME Challenge.
     * <p>
     * If the challenge has not been set or has already being cleared, it returns a 404 status code.
     * Otherwise, it clears the challenge and returns a 204 status code.
     *
     * @param rc the routing context
     */
    public void cleanupChallenge(RoutingContext rc) {
        if (challenge == null) {
            rc.response().setStatusCode(404).end();
        } else {
            challenge = null;
            rc.response().setStatusCode(204).end();
        }
    }

    /**
     * Set up the ACME HTTP 01 Challenge.
     * <p>
     * The body of the incoming request contains the challenge to be served.
     * </p>
     * <p>
     * Returns a 204 status code if the challenge has been set.
     * Returns a 400 status code if the challenge is already set.
     * </p>
     *
     * @param rc the routing context
     */
    private void setupChallenge(RoutingContext rc) {
        if (challenge != null) {
            LOGGER.warn("Let's Encrypt challenge already set");
            rc.response().setStatusCode(400).end();
        } else {
            challenge = rc.body().buffer();
            rc.response().setStatusCode(204).end();
        }
    }

    /**
     * Checks if the application is configured correctly to serve the Let's Encrypt challenge.
     * <p>
     * It verifies that the application is configured to use HTTPS (either using the default configuration) or using
     * the TLS configuration with the name indicated with the `key` query parameter.
     * </p>
     * <p>
     * Returns a 204 status code if the application is ready to serve the challenge (but the challenge is not yet configured),
     * and if the application is configured properly.
     * Returns a 200 status code if the challenge is already set, the response body contains the challenge.
     * Returns a 503 status code if the application is not configured properly.
     * </p>
     *
     * @param rc the routing context
     */
    public void ready(RoutingContext rc) {
        String key = rc.request().getParam("key");
        TlsConfiguration config;
        if (key == null) {
            key = TlsConfig.DEFAULT_NAME;
            config = registry.getDefault().orElse(null);
            if (config == null) {
                LOGGER.warn(
                        "Cannot handle Let's Encrypt flow - No default TLS configuration found. You must configure the quarkus.tls.* properties.");
                rc.response().setStatusCode(503).end();
                return;
            }
        } else {
            config = registry.get(key).orElse(null);
            if (config == null) {
                LOGGER.warn("Cannot handle Let's Encrypt flow - No " + key
                        + " TLS configuration found. You must configure the quarkus.tls." + key + ".* properties.");
                rc.response().setStatusCode(503).end();
                return;
            }
        }

        // Check that the key store is set.
        if (config.getKeyStore() == null) {
            LOGGER.warn("Cannot handle Let's Encrypt flow - No keystore configured in quarkus.tls."
                    + (key.equalsIgnoreCase(TlsConfig.DEFAULT_NAME) ? "" : key) + ".key-store");
            rc.response().setStatusCode(503).end();
            return;
        }

        // All good
        if (challenge == null) {
            rc.response().setStatusCode(204).end();
        } else {
            rc.response().end(challenge);
        }
    }

    public Handler<RoutingContext> reload() {
        // Registered as a blocking route, so we can fire the reload event in the same thread.
        return new Handler<RoutingContext>() {
            @Override
            public void handle(RoutingContext rc) {
                if (rc.request().method() != HttpMethod.POST) {
                    rc.response().setStatusCode(405).end();
                    return;
                }

                Optional<TlsConfiguration> configuration;
                String key = rc.request().getParam("key");
                if (key != null) {
                    configuration = registry.get(key);
                } else {
                    configuration = registry.getDefault();
                }

                if (configuration.isEmpty()) {
                    LOGGER.warn("Cannot reload certificate, no configuration found for "
                            + (key == null ? "quarkus.tls" : "quarkus.tls." + key));
                    rc.response().setStatusCode(404).end();
                } else {
                    rc.vertx().<Void> executeBlocking(new Callable<Void>() {
                        @Override
                        public Void call() {
                            if (configuration.get().reload()) {
                                event.fire(new CertificateUpdatedEvent((key == null ? TlsConfig.DEFAULT_NAME : key),
                                        configuration.get()));
                                rc.response().setStatusCode(204).end();
                            } else {
                                LOGGER.error("Failed to reload certificate");
                                rc.response().setStatusCode(500).end();
                            }
                            return null;
                        }
                    }, false);
                }
            }
        };
    }

    public Consumer<Route> setupCustomizer() {
        return new Consumer<Route>() {
            @Override
            public void accept(Route r) {
                r
                        .method(HttpMethod.POST)
                        .method(HttpMethod.GET)
                        .method(HttpMethod.DELETE)
                        .handler(BodyHandler.create());
            }
        };
    }

    public Handler<RoutingContext> chalengeAdminHandler() {
        return new Handler<RoutingContext>() {
            @Override
            public void handle(RoutingContext rc) {
                if (rc.request().method() == HttpMethod.POST) {
                    setupChallenge(rc);
                } else if (rc.request().method() == HttpMethod.DELETE) {
                    cleanupChallenge(rc);
                } else if (rc.request().method() == HttpMethod.GET) {
                    ready(rc);
                } else {
                    rc.response().setStatusCode(405).end();
                }
            }
        };
    }
}
