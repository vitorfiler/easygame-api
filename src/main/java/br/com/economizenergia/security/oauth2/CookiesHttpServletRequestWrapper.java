package br.com.economizenergia.security.oauth2;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

class CookiesHttpServletRequestWrapper extends HttpServletRequestWrapper {

    private Cookie[] cookies;

    public CookiesHttpServletRequestWrapper(HttpServletRequest request, Cookie[] cookies) {
        super(request);
        this.cookies = cookies;
    }

    @Override
    public Cookie[] getCookies() {
        return cookies;
    }
}
