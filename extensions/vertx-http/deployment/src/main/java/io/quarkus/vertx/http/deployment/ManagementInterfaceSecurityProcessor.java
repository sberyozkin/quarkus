package io.quarkus.vertx.http.deployment;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import jakarta.inject.Singleton;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerListenerBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.vertx.http.runtime.HttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.management.ManagementInterfaceBuildTimeConfig;
import io.quarkus.vertx.http.runtime.management.ManagementInterfaceSecurityRecorder;
import io.quarkus.vertx.http.runtime.security.BasicAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticator;
import io.quarkus.vertx.http.runtime.security.HttpAuthorizer;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;

public class ManagementInterfaceSecurityProcessor {

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    SyntheticBeanBuildItem initBasicAuth(
            HttpBuildTimeConfig httpBuildTimeConfig,
            ManagementInterfaceSecurityRecorder recorder,
            ManagementInterfaceBuildTimeConfig managementInterfaceBuildTimeConfig) {
        if (HttpSecurityProcessor.applicationBasicAuthRequired(httpBuildTimeConfig, managementInterfaceBuildTimeConfig)) {
            return null;
        }

        //basic auth explicitly disabled
        if (managementInterfaceBuildTimeConfig.auth.basic.orElse(false)) {
            SyntheticBeanBuildItem.ExtendedBeanConfigurator configurator = SyntheticBeanBuildItem
                    .configure(BasicAuthenticationMechanism.class)
                    .types(HttpAuthenticationMechanism.class)
                    .setRuntimeInit()
                    .scope(Singleton.class)
                    .supplier(recorder.setupBasicAuth());
            return configurator.done();
        }

        return null;
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    void setupAuthenticationMechanisms(
            ManagementInterfaceSecurityRecorder recorder,
            BuildProducer<ManagementInterfaceFilterBuildItem> filterBuildItemBuildProducer,
            BuildProducer<AdditionalBeanBuildItem> beanProducer,
            Capabilities capabilities,
            BuildProducer<BeanContainerListenerBuildItem> beanContainerListenerBuildItemBuildProducer,
            ManagementInterfaceBuildTimeConfig buildTimeConfig,
            List<HttpSecurityPolicyBuildItem> httpSecurityPolicyBuildItemList) {
        Map<String, Supplier<HttpSecurityPolicy>> policyMap = new HashMap<>();
        for (HttpSecurityPolicyBuildItem e : httpSecurityPolicyBuildItemList) {
            if (policyMap.containsKey(e.getName())) {
                throw new RuntimeException("Multiple HTTP security policies defined with name " + e.getName());
            }
            policyMap.put(e.getName(), e.policySupplier);
        }

        if (capabilities.isPresent(Capability.SECURITY)) {
            beanProducer
                    .produce(AdditionalBeanBuildItem.builder().setUnremovable().addBeanClass(HttpAuthenticator.class)
                            .addBeanClass(HttpAuthorizer.class).build());
            filterBuildItemBuildProducer
                    .produce(new ManagementInterfaceFilterBuildItem(
                            recorder.authenticationMechanismHandler(),
                            ManagementInterfaceFilterBuildItem.AUTHENTICATION));
            filterBuildItemBuildProducer
                    .produce(new ManagementInterfaceFilterBuildItem(recorder.permissionCheckHandler(buildTimeConfig, policyMap),
                            ManagementInterfaceFilterBuildItem.AUTHORIZATION));
        } else {
            if (!buildTimeConfig.auth.permissions.isEmpty()) {
                throw new IllegalStateException("HTTP permissions have been set however security is not enabled");
            }
        }
    }
}
