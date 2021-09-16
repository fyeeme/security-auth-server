package com.example.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;


@Slf4j
@Configuration
public class AuthorizationServerConfig   {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(){
        var registeredClient = RegisteredClient.withId("client")
                .clientId("client")
                .clientSecret(passwordEncoder.encode("client"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/authorized")
//                .redirectUri("http://2afc-58-100-81-50.ngrok.io/authorized")
//                .redirectUri("http://localhost:8080/login/oauth2/code/articles-client-oidc")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false) //是否展示授权同一页面，类似微信的授权页面一致
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .reuseRefreshTokens(false)
                        .accessTokenTimeToLive(Duration.ofMinutes(30L))
                        .refreshTokenTimeToLive(Duration.ofHours(2L))
                        .build())
                .scope(OidcScopes.OPENID)
                .scope("read")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public ProviderSettings providerSettings() {
       return  ProviderSettings.builder()
               .issuer("http://localhost:8080")
               .build();
    }
}
