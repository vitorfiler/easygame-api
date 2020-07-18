package br.com.economizenergia.security.oauth2;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Component;

@Component
public interface OAuth2TokenEndpointClient {

    OAuth2AccessToken sendPasswordGrant(String username, String password);

    OAuth2AccessToken sendRefreshGrant(String refreshTokenValue);
}
