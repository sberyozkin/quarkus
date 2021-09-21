package io.quarkus.kerberos;

import javax.security.auth.Subject;

public interface ServicePrincipalSubjectFactory {

    Subject getSubjectForServicePrincipal(String servicePrincipalName);
}
