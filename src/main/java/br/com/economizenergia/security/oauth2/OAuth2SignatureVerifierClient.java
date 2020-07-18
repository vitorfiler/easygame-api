package br.com.una.easygame.security.oauth2;

import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.stereotype.Component;

@Component
public interface OAuth2SignatureVerifierClient {
    SignatureVerifier getSignatureVerifier() throws Exception;
}
