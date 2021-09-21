package io.quarkus.kerberos.deployment;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.Feature;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.kerberos.runtime.KerberosAuthenticationMechanism;
import io.quarkus.kerberos.runtime.KerberosIdentityProvider;

public class KerberosBuildStep {

    @BuildStep
    public FeatureBuildItem featureBuildItem() {
        return new FeatureBuildItem(Feature.KERBEROS);
    }

    @BuildStep
    public void additionalBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans,
            BuildProducer<ReflectiveClassBuildItem> reflectiveClasses) {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable();

        builder.addBeanClass(KerberosAuthenticationMechanism.class)
                .addBeanClass(KerberosIdentityProvider.class);
        additionalBeans.produce(builder.build());
    }
}
