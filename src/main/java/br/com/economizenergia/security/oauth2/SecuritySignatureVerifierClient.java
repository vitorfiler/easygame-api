package br.com.economizenergia.security.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Component
public class SecuritySignatureVerifierClient implements OAuth2SignatureVerifierClient {

    @Autowired
    private RestTemplate restTemplate;

    @Override
    public SignatureVerifier getSignatureVerifier() throws Exception {
        try {
            HttpEntity<Void> request = new HttpEntity<>(new HttpHeaders());
            String key = (String) restTemplate
                .exchange(getPublicKeyEndpoint(), HttpMethod.GET, request, Map.class).getBody()
                .get("value");
            return new RsaVerifier(key);
        } catch (IllegalStateException ex) {
            return null;
        }
    }

    private String getPublicKeyEndpoint() {
        //TODO: parametrizar endpoint
        String tokenEndpointUrl = "http://localhost:1002/oauth/token_key";
        if (tokenEndpointUrl == null) {
            throw new InvalidClientException("no token endpoint configured in application properties");
        }
        return tokenEndpointUrl;
    }
}
