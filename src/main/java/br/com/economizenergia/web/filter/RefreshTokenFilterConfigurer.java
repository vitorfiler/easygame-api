package br.com.economizenergia.web.filter;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.DefaultSecurityFilterChain;

import br.com.economizenergia.security.oauth2.OAuth2AuthenticationService;

public class RefreshTokenFilterConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private OAuth2AuthenticationService authenticationService;
    private final TokenStore tokenStore;

    public RefreshTokenFilterConfigurer(OAuth2AuthenticationService authenticationService, TokenStore tokenStore) {
        this.authenticationService = authenticationService;
        this.tokenStore = tokenStore;
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        RefreshTokenFilter customFilter = new RefreshTokenFilter(authenticationService, tokenStore);
        builder.addFilterBefore(customFilter, OAuth2AuthenticationProcessingFilter.class);
    }
}
