package br.com.una.easygame.web.filter;

import br.com.una.easygame.security.oauth2.OAuth2AuthenticationService;
import br.com.una.easygame.security.oauth2.OAuth2CookieHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class RefreshTokenFilter extends GenericFilterBean {

    private static final int REFRESH_WINDOW_SECS = 30;

    private final OAuth2AuthenticationService authenticationService;
    private final TokenStore tokenStore;

    public RefreshTokenFilter(OAuth2AuthenticationService authenticationService, TokenStore tokenStore) {
        this.authenticationService = authenticationService;
        this.tokenStore = tokenStore;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        try {
            httpServletRequest = refreshTokenIfExpiring(httpServletRequest, httpServletResponse);
        } catch (ClientAuthenticationException ex) {
            log.debug("ClientAuthenticationException: {}", ex.getMessage());
            httpServletRequest = authenticationService.stripTokens(httpServletRequest);
        }
        filterChain.doFilter(httpServletRequest, servletResponse);
    }

    public HttpServletRequest refreshTokenIfExpiring(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        HttpServletRequest newHttpServletRequest = httpServletRequest;
        Cookie accessTokenCookie = OAuth2CookieHelper.getAccessTokenCookie(httpServletRequest);
        if (mustRefreshToken(accessTokenCookie)) {
            log.debug("refresh token");
            Cookie refreshCookie = OAuth2CookieHelper.getRefreshTokenCookie(httpServletRequest);
            if (refreshCookie != null) {
                try {
                    newHttpServletRequest = authenticationService.refreshToken(httpServletRequest, httpServletResponse, refreshCookie);
                } catch (HttpClientErrorException ex) {
                    log.debug("could not refresh OAuth2 token");
                    log.trace(ex.getMessage());
                    throw new UnauthorizedClientException("could not refresh OAuth2 token", ex);
                }
            } else if (accessTokenCookie != null) {
                OAuth2AccessToken token = tokenStore.readAccessToken(accessTokenCookie.getValue());
                if (token.isExpired()) {
                    log.debug("access token has expired, but there's no refresh token");
                    throw new InvalidTokenException("access token has expired, but there's no refresh token");
                }
            }
        }
        return newHttpServletRequest;
    }

    private boolean mustRefreshToken(Cookie accessTokenCookie) {
        if (accessTokenCookie == null) {
            log.debug("access token cookie is null");
            return true;
        }
        OAuth2AccessToken token = tokenStore.readAccessToken(accessTokenCookie.getValue());
        if (token.isExpired() || token.getExpiresIn() < REFRESH_WINDOW_SECS) {
            log.debug("access token expired");
            return true;
        }
        return false;
    }
}
