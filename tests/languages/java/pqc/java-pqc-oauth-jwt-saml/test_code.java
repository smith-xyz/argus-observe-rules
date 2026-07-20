package javapqcoauthjwtsaml;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.pac4j.core.client.Clients;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.opensaml.core.config.InitializationService;

public class TestCode {
    public void oauthFlow(
        ClientRegistrationRepository repo,
        OAuth2AuthorizedClientService service
    ) {
        OAuth2AuthorizedClientManager manager = new OAuth2AuthorizedClientManager(repo, service);
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest
            .withClientRegistrationId("client-id")
            .principal("user")
            .build();
        manager.authorize(request);
    }

    public void samlFlow() throws Exception {
        InitializationService.initialize();
        SAML2Configuration config = new SAML2Configuration("idp.xml", "sp.xml", "callback");
        SAML2Client client = new SAML2Client(config);
        Clients clients = new Clients("https://app.example.com/callback", client);
        clients.init();
    }
}
