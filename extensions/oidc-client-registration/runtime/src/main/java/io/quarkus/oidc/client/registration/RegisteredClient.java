package io.quarkus.oidc.client.registration;

import java.io.Closeable;

import io.smallrye.mutiny.Uni;

public interface RegisteredClient extends Closeable {
    ClientMetadata metadata();

    Uni<RegisteredClient> read();

    Uni<RegisteredClient> update(ClientMetadata metadata);

    Uni<Void> delete();
}
