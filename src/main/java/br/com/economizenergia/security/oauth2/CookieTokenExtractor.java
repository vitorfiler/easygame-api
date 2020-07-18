package br.com.economizenergia.security.oauth2;

import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class CookieTokenExtractor extends BearerTokenExtractor {

    @Override
    protected String extractToken(HttpServletRequest request) {
        String result;
        Cookie accessTokenCookie = OAuth2CookieHelper.getAccessTokenCookie(request);
        if (accessTokenCookie != null) {
            result = accessTokenCookie.getValue();
        } else {
            result = super.extractToken(request);
        }
        return result;
    }
}
