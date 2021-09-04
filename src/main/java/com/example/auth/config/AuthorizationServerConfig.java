package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.time.Duration;
import java.util.function.Consumer;


@Configuration
@EnableWebSecurity
@Import(OAuth2AuthorizationServerConfiguration.class)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class AuthorizationServerConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public UserDetailsService userDetailsService() {
        var userDetailsManager = new InMemoryUserDetailsManager();

        var user = User.withUsername("admin")
                .password("admin")
                .authorities("read")
                .build();
        userDetailsManager.createUser(user);
        return userDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(){
        var registeredClient = RegisteredClient.withId("client")
                .clientId("client")
                .clientSecret("client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/authorized")
                .tokenSettings(tokenSettings -> {
                    tokenSettings.enableRefreshTokens(true); //toggle enable refresh token
                    tokenSettings.reuseRefreshTokens(true);// 禁止重复使用刷新 refresh token
                    tokenSettings.accessTokenTimeToLive(Duration.ofHours(2L));
                })
                .scope("read")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }
    @Bean
    public KeyManager keyManager(){
        return new StaticKeyGeneratingKeyManager();
    }

}
