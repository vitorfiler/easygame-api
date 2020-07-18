package br.com.una.easygame.security.oauth2;

import org.apache.http.conn.util.PublicSuffixMatcher;
import org.apache.http.conn.util.PublicSuffixMatcherLoader;
import org.springframework.boot.json.JsonParser;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.apache.http.conn.util.InetAddressUtils.isIPv4Address;
import static org.apache.http.conn.util.InetAddressUtils.isIPv6Address;

@Component
public class OAuth2CookieHelper {
    public static final String ACCESS_TOKEN_COOKIE = OAuth2AccessToken.ACCESS_TOKEN;
    public static final String REFRESH_TOKEN_COOKIE = OAuth2AccessToken.REFRESH_TOKEN;
    public static final String SESSION_TOKEN_COOKIE = "session_token";
    private static final List<String> COOKIE_NAMES = Arrays.asList(ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, SESSION_TOKEN_COOKIE);
    private static final long REFRESH_TOKEN_EXPIRATION_WINDOW_SECS = 3L;
    PublicSuffixMatcher suffixMatcher;
    private JsonParser jsonParser = JsonParserFactory.getJsonParser();

    public OAuth2CookieHelper() {
        this.suffixMatcher = PublicSuffixMatcherLoader.getDefault();
    }

    public void createCookies(HttpServletRequest request, OAuth2AccessToken accessToken, boolean rememberMe, OAuth2Cookies result) {
        String domain = getCookieDomain(request);
        Cookie accessTokenCookie = new Cookie(ACCESS_TOKEN_COOKIE, accessToken.getValue());
        setCookieProperties(accessTokenCookie, request.isSecure(), domain);
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        Cookie refreshTokenCookie = createRefreshTokenCookie(refreshToken, rememberMe);
        setCookieProperties(refreshTokenCookie, request.isSecure(), domain);
        result.setCookies(accessTokenCookie, refreshTokenCookie);
    }

    private Cookie createRefreshTokenCookie(OAuth2RefreshToken refreshToken, boolean rememberMe) {
        int maxAge = -1;
        String name = SESSION_TOKEN_COOKIE;
        String value = refreshToken.getValue();
        if (rememberMe) {
            name = REFRESH_TOKEN_COOKIE;
            Integer exp = getClaim(refreshToken.getValue(), AccessTokenConverter.EXP, Integer.class);
            if (exp != null) {
                int now = (int) (System.currentTimeMillis() / 1000L);
                maxAge = exp - now;
                maxAge -= REFRESH_TOKEN_EXPIRATION_WINDOW_SECS;
            }
        }
        Cookie refreshTokenCookie = new Cookie(name, value);
        refreshTokenCookie.setMaxAge(maxAge);
        return  refreshTokenCookie;
    }

    private String getCookieDomain(HttpServletRequest request) {
        //TODO: parametrizar cookie-domain
        String domain = request.getServerName().toLowerCase();
        if (domain.startsWith("www.")) {
            domain = domain.substring(4);
        }
        if (!isIPv4Address(domain) && !isIPv6Address(domain)) {
            String suffix = suffixMatcher.getDomainRoot(domain);
            if (suffix != null && !suffix.equals(domain)) {
                return "." + suffix;
            }
        }
        return null;
    }

    private void setCookieProperties(Cookie cookie, boolean isSecure, String domain) {
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(isSecure);
        if (domain != null) {
            cookie.setDomain(domain);
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T getClaim(String refreshToken, String claimName, Class<T> clazz) {
        Jwt jwt = JwtHelper.decode(refreshToken);
        String claims = jwt.getClaims();
        Map<String, Object> claimsMap = jsonParser.parseMap(claims);
        Object claimValue = claimsMap.get(claimName);
        if (claimValue == null) {
            return null;
        }
        if (!clazz.isAssignableFrom(claimValue.getClass())) {
            throw new InvalidTokenException("claim is not of expected type: " + claimName);
        }
        return (T) claimValue;
    }

    public static Cookie getAccessTokenCookie(HttpServletRequest request) {
        return getCookie(request, ACCESS_TOKEN_COOKIE);
    }

    public static Cookie getRefreshTokenCookie(HttpServletRequest request) {
        Cookie cookie = getCookie(request, REFRESH_TOKEN_COOKIE);
        if (cookie == null) {
            cookie = getCookie(request, SESSION_TOKEN_COOKIE);
        }
        return cookie;
    }

    private static Cookie getCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(cookieName)) {
                    String value = cookie.getValue();
                    if (StringUtils.hasText(value)) {
                        return cookie;
                    }
                }
            }
        }
        return null;
    }

    public boolean isSessionExpired(Cookie refreshCookie) {
        if (isRememberMe(refreshCookie)) {
            return false;
        }
        //TODO: parametrizar validity
        int validity = 1800;
        if (validity < 0) {
            return false;
        }
        Integer iat = getClaim(refreshCookie.getValue(), "iat", Integer.class);
        if (iat == null) {
            return false;
        }
        int now = (int) (System.currentTimeMillis() / 1000L);
        int sessionDuration = now - iat;
        return sessionDuration > validity;
    }

    public static boolean isRememberMe(Cookie refreshTokenCookie) {
        return refreshTokenCookie.getName().equals(REFRESH_TOKEN_COOKIE);
    }

    public static String getRefreshTokenValue(Cookie refreshCookie) {
        String value = refreshCookie.getValue();
        int i = value.indexOf('|');
        if (i > 0) {
            return value.substring(i + 1);
        }
        return value;
    }

    public void clearCookies(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        String domain = getCookieDomain(httpServletRequest);
        for (String cookieName : COOKIE_NAMES) {
            clearCookie(httpServletRequest, httpServletResponse, domain, cookieName);
        }
    }

    private void clearCookie(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, String domain, String cookieName) {
        Cookie cookie = new Cookie(cookieName, "");
        setCookieProperties(cookie, httpServletRequest.isSecure(), domain);
        cookie.setMaxAge(0);
        httpServletResponse.addCookie(cookie);
    }

    Cookie[] stripCookies(Cookie[] cookies) {
        CookieCollection cc = new CookieCollection(cookies);
        if (cc.removeAll(COOKIE_NAMES)) {
            return cc.toArray();
        }
        return cookies;
    }
}
