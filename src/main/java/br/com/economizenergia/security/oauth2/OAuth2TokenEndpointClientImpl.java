package br.com.economizenergia.security.oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;

@Component
public class OAuth2TokenEndpointClientImpl extends OAuth2TokenEndpointClientAdapter implements OAuth2TokenEndpointClient {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Override
    protected void addAuthentication(HttpHeaders reqHeaders, MultiValueMap<String, String> formParams) {
        reqHeaders.add("Authorization", getAuthorizationHeader());
    }

    protected String getAuthorizationHeader() {
        //TODO: parametrizar clientId e clientSecret - podem ser implementados na classe abstrata
        String clientId = "web_app";
        String clientSecret = "changeit";
        String authorization = clientId + ":" + clientSecret;
        return "Basic " + Base64Utils.encodeToString(authorization.getBytes(StandardCharsets.UTF_8));
    }
}
