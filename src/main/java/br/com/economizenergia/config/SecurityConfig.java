package br.com.una.easygame.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import br.com.una.easygame.security.oauth2.OAuth2SignatureVerifierClient;

//@Configuration
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//@EnableResourceServer
public class SecurityConfig extends ResourceServerConfigurerAdapter {

//    @Autowired
//    private CorsFilter corsFilter;

    @Autowired
    OAuth2SignatureVerifierClient signatureVerifierClient;

    @Override
    public void configure(HttpSecurity http) throws Exception {
//        http
//            .csrf()
//            .ignoringAntMatchers("/h2-console/**")
//            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//        .and()
////            .addFilterBefore(corsFilter, CsrfFilter.class)
//            .headers()
//            .frameOptions()
//            .disable()
//        .and()
//            .sessionManagement()
//            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        .and()
//            .authorizeRequests()
//            .antMatchers("/auth/login").permitAll();
//        .and()
//            .authorizeRequests()
//            .antMatchers("/core/**").authenticated();
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        return new OAuth2JwtAccessTokenConverter(this.signatureVerifierClient);
    }


}
