package io.quarkus.it.smallrye.config;

import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonProperty;

public interface Named {
    @JsonProperty
    Optional<String> name();
}
