package io.quarkus.oidc.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.gargoylesoftware.htmlunit.SilentCssErrorHandler;
import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.keycloak.server.KeycloakTestResourceLifecycleManager;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@QuarkusTestResource(KeycloakTestResourceLifecycleManager.class)
public class CodeTenantReauthenticateTestCase {

    private static Class<?>[] testClasses = {
            TenantReauthentication.class,
            CustomTenantResolver.class,
            CustomTenantConfigResolver.class
    };

    @RegisterExtension
    static final QuarkusUnitTest test = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(testClasses)
                    .addAsResource("application-tenant-reauthenticate.properties", "application.properties"));

    @Test
    public void testDefaultTenant() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected", "alice");

            webClient.getCookieManager().clearCookies();
        }
    }

    @Test
    public void testTenantResolver() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected/tenant/tenant-resolver", "tenant-resolver:alice");

            webClient.getCookieManager().clearCookies();
        }
    }

    @Test
    public void testTenantConfigResolver() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected/tenant/tenant-config-resolver", "tenant-config-resolver:alice");

            webClient.getCookieManager().clearCookies();
        }
    }

    @Test
    public void testSwitchFromTenantResolverToDefaultTenant() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected/tenant/tenant-resolver", "tenant-resolver:alice");
            expectReauthentication(webClient, "/protected");

            webClient.getCookieManager().clearCookies();
        }
    }

    @Test
    public void testSwitchFromDefaultTenantToTenantResover() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected", "alice");
            expectReauthentication(webClient, "/protected/tenant/tenant-resolver");

            webClient.getCookieManager().clearCookies();
        }
    }

    @Test
    public void testSwitchFromTenantConfigResolverToDefaultTenant() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected/tenant/tenant-config-resolver", "tenant-config-resolver:alice");
            expectReauthentication(webClient, "/protected");

            webClient.getCookieManager().clearCookies();
        }
    }

    @Test
    public void testSwitchFromDefaultTenantToTenantConfigResolver() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected", "alice");
            expectReauthentication(webClient, "/protected/tenant/tenant-config-resolver");

            webClient.getCookieManager().clearCookies();
        }
    }

    @Test
    public void testSwitchFromTenantResolverToTenantConfigResolver() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected/tenant/tenant-resolver", "tenant-resolver:alice");
            expectReauthentication(webClient, "/protected/tenant/tenant-config-resolver");

            webClient.getCookieManager().clearCookies();
        }
    }

    @Test
    public void testSwitchFromTenantConfigResolverToTenantResolver() throws Exception {
        try (final WebClient webClient = createWebClient()) {

            callTenant(webClient, "/protected/tenant/tenant-config-resolver", "tenant-config-resolver:alice");
            expectReauthentication(webClient, "/protected/tenant/tenant-resolver");

            webClient.getCookieManager().clearCookies();
        }
    }

    private static void callTenant(WebClient webClient, String relativePath, String expectedResponse) throws Exception {
        HtmlPage page = webClient.getPage("http://localhost:8081" + relativePath);

        assertEquals("Sign in to quarkus", page.getTitleText());

        HtmlForm loginForm = page.getForms().get(0);

        loginForm.getInputByName("username").setValueAttribute("alice");
        loginForm.getInputByName("password").setValueAttribute("alice");

        page = loginForm.getInputByName("login").click();

        assertEquals(expectedResponse, page.getBody().asNormalizedText());
    }

    private static void expectReauthentication(WebClient webClient, String relativePath) throws Exception {
        webClient.getOptions().setRedirectEnabled(false);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);

        TextPage textPage = webClient.getPage("http://localhost:8081" + relativePath);
        assertEquals(302, textPage.getWebResponse().getStatusCode());
    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        return webClient;
    }
}
