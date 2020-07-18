package br.com.economizenergia.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import br.com.economizenergia.security.oauth2.CookieTokenExtractor;
import br.com.economizenergia.security.oauth2.OAuth2AuthenticationService;
import br.com.economizenergia.security.oauth2.OAuth2CookieHelper;
import br.com.economizenergia.security.oauth2.OAuth2SignatureVerifierClient;
import br.com.economizenergia.security.oauth2.OAuth2TokenEndpointClient;
import br.com.economizenergia.security.oauth2.SecuritySignatureVerifierClient;
import br.com.economizenergia.web.filter.RefreshTokenFilterConfigurer;

@Configuration
@EnableResourceServer
public class OAuth2AuthenticationConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private OAuth2TokenEndpointClient tokenEndpointClient;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    OAuth2SignatureVerifierClient signatureVerifierClient;

//    @Autowired
//    private CorsFilter corsFilter;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/auth/login").permitAll()
            .antMatchers("/core/**").authenticated();
//            .antMatchers("/auth/logout").authenticated()
//        .and()
//            .apply(refreshTokenSecurityConfigurerAdapter());
//        .and()
//            .csrf()
//            .ignoringAntMatchers("/h2-console/**");

        http
            .csrf()
            .ignoringAntMatchers("/h2-console/**")
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .and()
//            .addFilterBefore(corsFilter, CsrfFilter.class)
            .headers()
            .frameOptions()
            .disable()
        .and()
            .apply(refreshTokenSecurityConfigurerAdapter())
        .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.csrf().disable();
    }

    private RefreshTokenFilterConfigurer refreshTokenSecurityConfigurerAdapter() {
        return new RefreshTokenFilterConfigurer(authenticationService(), tokenStore);
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenExtractor(tokenExtractor());
    }

    @Bean
    public OAuth2AuthenticationService authenticationService() {
        return new OAuth2AuthenticationService(tokenEndpointClient, cookieHelper());
    }

    @Bean
    public OAuth2CookieHelper cookieHelper() {
        return new OAuth2CookieHelper();
    }

    @Bean
    public TokenExtractor tokenExtractor() {
        return new CookieTokenExtractor();
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        return new OAuth2JwtAccessTokenConverter(signatureVerifierClient());
    }

    @Bean
    public OAuth2SignatureVerifierClient signatureVerifierClient() {
        return new SecuritySignatureVerifierClient();
    }
}
