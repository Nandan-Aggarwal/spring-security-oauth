package com.baeldung.newstack.spring;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.StringUtils;

import java.util.Collection;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String SUPERUSER = "SUPERUSER";
    public static final String BAELDUNG = "@baeldung.com";

    @Override
    protected void configure(HttpSecurity http) throws Exception {// @formatter:off
        http.authorizeRequests()
              .antMatchers(HttpMethod.GET, "/user/info", "/api/projects/**")
                .hasAuthority("SCOPE_read")
              .antMatchers(HttpMethod.POST, "/api/projects/")
                .hasAuthority(SUPERUSER)
              .anyRequest()
                .authenticated()
            .and()
              .oauth2ResourceServer()
                .jwt(jwtConfigurer ->
                    jwtConfigurer.jwtAuthenticationConverter(customAuthenticationConverter())
                );
    }//@formatter:on

    private JwtAuthenticationConverter customAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(customGrantedAuthoritiesConverter());
        return converter;
    }

    private Converter<Jwt, Collection<GrantedAuthority>> customGrantedAuthoritiesConverter() {
        JwtGrantedAuthoritiesConverter defaultConverter = new JwtGrantedAuthoritiesConverter();
        return jwt -> {
            Collection<GrantedAuthority> authorities = defaultConverter.convert(jwt);

            String preferredUsername = jwt.getClaimAsString("preferred_username");
            if (!StringUtils.isEmpty(preferredUsername) && preferredUsername.endsWith(BAELDUNG)) {
                authorities.add(new SimpleGrantedAuthority(SUPERUSER));
            }

            return authorities;
        };
    }
}