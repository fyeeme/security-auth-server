package com.example.auth.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Configuration
public class ResourceServerConfig {
    /**
     * Jwt decoder jwt decoder.
     *
     * @param jwkSource the jwk source
     * @return the jwt decoder
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        JWSVerificationKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
//
//        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
//        jwtProcessor.setJWSKeySelector(keySelector);
//
//        return new NimbusJwtDecoder(jwtProcessor);
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
