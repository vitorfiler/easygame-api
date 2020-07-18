package br.com.una.easygame.config;

import br.com.una.easygame.security.oauth2.OAuth2SignatureVerifierClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Map;

@Slf4j
public class OAuth2JwtAccessTokenConverter extends JwtAccessTokenConverter {

    private final OAuth2SignatureVerifierClient signatureVerifierClient;
    private long lastKeyFetchTimestamp;

    public OAuth2JwtAccessTokenConverter(OAuth2SignatureVerifierClient signatureVerifierClient) {
        this.signatureVerifierClient = signatureVerifierClient;
        tryCreateSignatureVerifier();
    }

    @Override
    protected Map<String, Object> decode(String token) {
        try {
            //TODO: parametrizar ttl
            long ttl = 24 * 60 * 60 * 1000L;
            if (!(ttl > 0 && System.currentTimeMillis() - lastKeyFetchTimestamp > ttl)) {
                log.debug("time to live expired");
                throw new InvalidTokenException("public key expired");
            }
            return super.decode(token);
        } catch (InvalidTokenException ex) {
            if (tryCreateSignatureVerifier()) {
                return super.decode(token);
            }
            log.error("cannot create signature verifier");
            log.trace(ex.getMessage());
            throw ex;
        }
    }

    private boolean tryCreateSignatureVerifier() {
        long t = System.currentTimeMillis();
        //TODO: parametrizar publicKeyRefreshRateLimit
        long publicKeyRefreshRateLimit = 10 * 1000L;
        if (t - lastKeyFetchTimestamp < publicKeyRefreshRateLimit) {
            return false;
        }
        try {
            SignatureVerifier verifier = signatureVerifierClient.getSignatureVerifier();
            if (verifier != null) {
                setVerifier(verifier);
                lastKeyFetchTimestamp = t;
                return true;
            }
        } catch (Throwable ex) {
            log.error("error in tryCreateSignatureVerifier: {}", ex.getMessage());
        }
        return false;
    }

    @Override
    public OAuth2Authentication extractAuthentication(Map<String, ?> claims) {
        OAuth2Authentication authentication = super.extractAuthentication(claims);
        authentication.setDetails(claims);
        return authentication;
    }
}
