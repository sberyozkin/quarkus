package io.quarkus.oidcvc.deployment;

import java.util.function.BooleanSupplier;

import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.jandex.DotName;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.Feature;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.ExtensionSslNativeSupportBuildItem;
import io.quarkus.oidcvc.runtime.OidcCodeFlowRedirectFilter;
import io.quarkus.oidcvc.runtime.OidcVerifiableCredentialsRecorder;
import io.quarkus.oidcvc.runtime.VerifiableCredentialAction;
import io.quarkus.oidcvc.runtime.VerifiableCredentialMetadataProducer;
import io.quarkus.oidcvc.runtime.VerifiableCredentialProducer;
import io.quarkus.oidcvc.runtime.VerifiableCredentialResolver;
import io.quarkus.proxy.deployment.ProxyRegistryBuildItem;
import io.quarkus.tls.deployment.spi.TlsRegistryBuildItem;
import io.quarkus.vertx.core.deployment.CoreVertxBuildItem;

@BuildSteps(onlyIf = OidcVerifiableCredentialsBuildStep.IsEnabled.class)
public class OidcVerifiableCredentialsBuildStep {

    private static final DotName VERIFIABLE_CREDENTIAL_RESOLVER = DotName
            .createSimple(VerifiableCredentialResolver.class.getName());

    @BuildStep
    ExtensionSslNativeSupportBuildItem enableSslInNative() {
        return new ExtensionSslNativeSupportBuildItem(Feature.OIDC_VERIFIABLE_CREDENTIALS);
    }

    @BuildStep
    public void additionalBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans) {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable();
        builder.addBeanClass(VerifiableCredentialProducer.class);
        builder.addBeanClass(VerifiableCredentialMetadataProducer.class);
        builder.addBeanClass(VerifiableCredentialAction.class);
        builder.addBeanClass(OidcCodeFlowRedirectFilter.class);
        additionalBeans.produce(builder.build());
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    public void generateBean(
            OidcVerifiableCredentialsRecorder recorder,
            BuildProducer<SyntheticBeanBuildItem> beanProducer,
            CoreVertxBuildItem vertxBuildItem,
            TlsRegistryBuildItem tlsRegistryBuildItem,
            ProxyRegistryBuildItem proxyRegistryBuildItem) {
        beanProducer.produce(SyntheticBeanBuildItem
                .configure(VERIFIABLE_CREDENTIAL_RESOLVER)
                .setRuntimeInit()
                .defaultBean()
                .scope(ApplicationScoped.class)
                .supplier(recorder.setup(vertxBuildItem.getVertx(), tlsRegistryBuildItem.registry(),
                        proxyRegistryBuildItem.registry()))
                .done());
    }

    public static class IsEnabled implements BooleanSupplier {
        OidcVerifiableCredentialsBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled();
        }
    }
}
