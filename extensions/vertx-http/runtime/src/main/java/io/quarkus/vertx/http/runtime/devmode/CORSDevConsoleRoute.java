package io.quarkus.vertx.http.runtime.devmode;

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import io.quarkus.vertx.http.runtime.cors.CORSConfig;
import io.quarkus.vertx.http.runtime.cors.CORSFilter;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.RoutingContext;

public class CORSDevConsoleRoute implements Consumer<Route> {

    private Handler<RoutingContext> handler = new DevConsoleCORSFilter();

    public CORSDevConsoleRoute() {
    }

    @Override
    public void accept(Route route) {
        route.order(-200);
        route.handler(handler);
    }

    private static class DevConsoleCORSFilter extends CORSFilter {

        public DevConsoleCORSFilter() {
            super(corsConfig());
        }

        private static CORSConfig corsConfig() {
            CORSConfig config = new CORSConfig();
            config.origins = Optional.of(List.of("http://localhost", "https://localhost"));
            return config;
        }

        @Override
        public void handle(RoutingContext event) {
            HttpServerRequest request = event.request();
            HttpServerResponse response = event.response();
            String origin = request.getHeader(HttpHeaders.ORIGIN);
            if (origin == null) {
                event.next();
            } else {
                if (!origin.contains("localhost")) {
                    response.end();
                } else {
                    super.handle(event);
                }
            }
        }
    }
}
