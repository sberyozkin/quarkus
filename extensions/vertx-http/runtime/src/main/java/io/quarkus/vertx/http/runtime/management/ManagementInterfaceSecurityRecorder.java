package io.quarkus.vertx.http.runtime.management;

import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

import jakarta.enterprise.inject.spi.CDI;

import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.arc.runtime.BeanContainerListener;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.BasicAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticator;
import io.quarkus.vertx.http.runtime.security.HttpAuthorizer;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.quarkus.vertx.http.runtime.security.HttpSecurityRecorder;
import io.quarkus.vertx.http.runtime.security.PathMatchingHttpSecurityPolicy;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.subscription.UniSubscriber;
import io.smallrye.mutiny.subscription.UniSubscription;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

@Recorder
public class ManagementInterfaceSecurityRecorder {

    final RuntimeValue<ManagementInterfaceConfiguration> httpConfiguration;
    final ManagementInterfaceBuildTimeConfig buildTimeConfig;

    public ManagementInterfaceSecurityRecorder(RuntimeValue<ManagementInterfaceConfiguration> httpConfiguration,
            ManagementInterfaceBuildTimeConfig buildTimeConfig) {
        this.httpConfiguration = httpConfiguration;
        this.buildTimeConfig = buildTimeConfig;
    }

    public Handler<RoutingContext> authenticationMechanismHandler() {
        return new Handler<RoutingContext>() {

            volatile HttpAuthenticator authenticator;

            @Override
            public void handle(RoutingContext event) {
                if (authenticator == null) {
                    authenticator = CDI.current().select(HttpAuthenticator.class).get();
                }
                //we put the authenticator into the routing context so it can be used by other systems
                event.put(HttpAuthenticator.class.getName(), authenticator);

                //register the default auth failure handler
                event.put(QuarkusHttpUser.AUTH_FAILURE_HANDLER, new HttpSecurityRecorder.DefaultAuthFailureHandler() {
                    @Override
                    protected void proceed(Throwable throwable) {

                        if (!event.failed()) {
                            //failing event makes it possible to customize response via failure handlers
                            //QuarkusErrorHandler will send response if no other failure handler did
                            event.fail(throwable);
                        }
                    }
                });

                Uni<SecurityIdentity> potentialUser = authenticator.attemptAuthentication(event).memoize().indefinitely();
                potentialUser
                        .subscribe().withSubscriber(new UniSubscriber<SecurityIdentity>() {
                            @Override
                            public void onSubscribe(UniSubscription subscription) {

                            }

                            @Override
                            public void onItem(SecurityIdentity identity) {
                                if (event.response().ended()) {
                                    return;
                                }
                                if (identity == null) {
                                    Uni<SecurityIdentity> anon = authenticator.getIdentityProviderManager()
                                            .authenticate(AnonymousAuthenticationRequest.INSTANCE);
                                    anon.subscribe().withSubscriber(new UniSubscriber<SecurityIdentity>() {
                                        @Override
                                        public void onSubscribe(UniSubscription subscription) {

                                        }

                                        @Override
                                        public void onItem(SecurityIdentity item) {
                                            event.put(QuarkusHttpUser.DEFERRED_IDENTITY_KEY, anon);
                                            event.setUser(new QuarkusHttpUser(item));
                                            event.next();
                                        }

                                        @Override
                                        public void onFailure(Throwable failure) {
                                            BiConsumer<RoutingContext, Throwable> handler = event
                                                    .get(QuarkusHttpUser.AUTH_FAILURE_HANDLER);
                                            if (handler != null) {
                                                handler.accept(event, failure);
                                            }
                                        }
                                    });
                                } else {//when the result is evaluated we set the user, even if it is evaluated lazily
                                    event.setUser(new QuarkusHttpUser(identity));
                                    event.put(QuarkusHttpUser.DEFERRED_IDENTITY_KEY, potentialUser);
                                    event.next();
                                }
                            }

                            @Override
                            public void onFailure(Throwable failure) {
                                //this can be customised
                                BiConsumer<RoutingContext, Throwable> handler = event
                                        .get(QuarkusHttpUser.AUTH_FAILURE_HANDLER);
                                if (handler != null) {
                                    handler.accept(event, failure);
                                }

                            }
                        });

            }
        };
    }

    public Handler<RoutingContext> permissionCheckHandler() {
        return new Handler<RoutingContext>() {
            volatile HttpAuthorizer authorizer;

            @Override
            public void handle(RoutingContext event) {
                if (authorizer == null) {
                    authorizer = CDI.current().select(HttpAuthorizer.class).get();
                }
                authorizer.checkPermission(event);
            }
        };
    }

    public BeanContainerListener initPermissions(ManagementInterfaceBuildTimeConfig buildTimeConfig,
            Map<String, Supplier<HttpSecurityPolicy>> policies) {
        return new BeanContainerListener() {
            @Override
            public void created(BeanContainer container) {
                container.beanInstance(PathMatchingHttpSecurityPolicy.class)
                        .init(buildTimeConfig.auth.permissions, policies, buildTimeConfig.rootPath);
            }
        };
    }

    public Supplier<?> setupBasicAuth() {
        return new Supplier<BasicAuthenticationMechanism>() {
            @Override
            public BasicAuthenticationMechanism get() {
                return new BasicAuthenticationMechanism(null, false);
            }
        };
    }

}
