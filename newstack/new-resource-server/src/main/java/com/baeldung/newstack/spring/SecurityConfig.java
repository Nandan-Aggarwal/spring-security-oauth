package com.baeldung.newstack.spring;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;

import javax.validation.constraints.Email;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Override
    protected void configure(HttpSecurity http) throws Exception {// @formatter:off
        http.authorizeRequests()
              .antMatchers(HttpMethod.GET, "/user/info", "/api/projects/**")
                .hasAuthority("SCOPE_read")
              .antMatchers(HttpMethod.POST, "/api/projects")
                .hasAuthority("SCOPE_write")
              .anyRequest()
                .authenticated()
            .and()
              .oauth2ResourceServer()
                .jwt();
    }//@formatter:on

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri);
        OAuth2TokenValidator<Jwt> defaultValidator = JwtValidators.createDefault();

        OAuth2TokenValidator<Jwt> delegatingOAuth2TokenValidator = new DelegatingOAuth2TokenValidator<>(defaultValidator, this::validatePreferredUserName);

        jwtDecoder.setJwtValidator(delegatingOAuth2TokenValidator);

        return jwtDecoder;
    }

    private OAuth2TokenValidatorResult validatePreferredUserName(Jwt jwt) {
        if (jwt.getClaimAsString("preferred_username").endsWith("@baeldung.com")) {
            return OAuth2TokenValidatorResult.success();
        } else {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid user domain"));
        }
    }
}