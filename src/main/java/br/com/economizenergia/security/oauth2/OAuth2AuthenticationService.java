package br.com.economizenergia.security.oauth2;

import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class OAuth2AuthenticationService {

    //private static final long REFRESH_TOKEN_VALIDITY_MILLIS = 10000L;

    private final OAuth2TokenEndpointClient authorizationClient;
    private final OAuth2CookieHelper cookieHelper;

    public OAuth2AuthenticationService(OAuth2TokenEndpointClient authorizationClient, OAuth2CookieHelper cookieHelper) {
        this.authorizationClient = authorizationClient;
        this.cookieHelper = cookieHelper;
    }

    //TODO: cachear token
//    private final PersistentTokenCache<OAuth2Cookies> recentlyRefreshed;

    public ResponseEntity<OAuth2AccessToken> authenticate(HttpServletRequest request, HttpServletResponse response, Map<String, String> params) {
        try {
            String username = params.get("username");
            String password = params.get("password");
            boolean rememberMe = Boolean.parseBoolean(params.get("rememberMe"));
            OAuth2AccessToken accessToken = authorizationClient.sendPasswordGrant(username, password);
            OAuth2Cookies cookies = new OAuth2Cookies();
            cookieHelper.createCookies(request, accessToken, rememberMe, cookies);
            cookies.addCookiesTo(response);
            return  ResponseEntity.ok(accessToken);
        } catch (HttpClientErrorException ex) {
            log.error("invalid credentials: {}", ex.getMessage());
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    public HttpServletRequest refreshToken(HttpServletRequest request, HttpServletResponse response, Cookie refreshCookie) {
        if (cookieHelper.isSessionExpired(refreshCookie)) {
            log.debug("session expired");
            logout(request, response);
            return stripTokens(request);
        }
        OAuth2Cookies cookies = new OAuth2Cookies(); //getCachedCookies(refreshCookie.getValue());
//        synchronized (cookies) {
            if (cookies.getAccessTokenCookie() == null) {
                String refreshCookieValue = OAuth2CookieHelper.getRefreshTokenValue(refreshCookie);
                OAuth2AccessToken accessToken = authorizationClient.sendRefreshGrant(refreshCookieValue);
                boolean rememberMe = OAuth2CookieHelper.isRememberMe(refreshCookie);
                cookieHelper.createCookies(request, accessToken, rememberMe, cookies);
                cookies.addCookiesTo(response);
            } else {
                log.debug("access token cookie already exists");
            }
            CookieCollection requestCookies = new CookieCollection(request.getCookies());
            requestCookies.add(cookies.getAccessTokenCookie());
            requestCookies.add(cookies.getRefreshTokenCookie());
            return new CookiesHttpServletRequestWrapper(request, requestCookies.toArray());
//        }
    }

//    private OAuth2Cookies getCachedCookies(String refreshTokenValue) {
//        synchronized (recentlyRefreshed) {
//            OAuth2Cookies ctx = recentlyRefreshed.get(refreshTokenValue);
//            if (ctx == null) {
//                ctx = new OAuth2Cookies();
//                recentlyRefreshed.put(refreshTokenValue, ctx);
//            }
//            return ctx;
//        }
//    }

    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        cookieHelper.clearCookies(httpServletRequest, httpServletResponse);
    }

    public HttpServletRequest stripTokens(HttpServletRequest httpServletRequest) {
        Cookie[] cookies = cookieHelper.stripCookies(httpServletRequest.getCookies());
        return new CookiesHttpServletRequestWrapper(httpServletRequest, cookies);
    }
}
