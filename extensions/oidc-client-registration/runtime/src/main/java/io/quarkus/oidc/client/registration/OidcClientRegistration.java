package io.quarkus.oidc.client.registration;

import java.io.Closeable;
import java.util.List;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;

public interface OidcClientRegistration extends Closeable {
    Uni<RegisteredClient> registerClient();

    Uni<RegisteredClient> registerClient(ClientMetadata reg);

    Multi<RegisteredClient> registerClients(List<ClientMetadata> regs);

}
