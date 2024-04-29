package com.keplara.auth_service.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.disable())
            .authorizeHttpRequests((authorizeHttpRequests) ->
                authorizeHttpRequests
                    .requestMatchers(HttpMethod.POST, "/login").permitAll()
                    .requestMatchers(HttpMethod.POST, "/create-account").permitAll()
                    .requestMatchers(HttpMethod.GET, "/verify-new-account").permitAll()
                    .requestMatchers(HttpMethod.POST, "/reset-password").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.POST, "/create-product").hasAuthority("create.product")
                    .requestMatchers(HttpMethod.PUT, "/update-product").hasAuthority("update.product")
                    .anyRequest().authenticated()
            );
        return http.build();
    }
}