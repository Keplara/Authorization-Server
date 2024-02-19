package com.keplara.auth_service.configuration;

// enable cors
// enable cross site forgery 
// filter 1 JWT Authenticaiton Filter session attach to user object context 
// filter 2 OAuth 2 2 leg custom service because we cannot rely on the External providers
// filter Device Location
// AuthenticateProvider

// Logins
// SSO
// user & password
// 2 factor phone or email return boolean as confirmed and a redirect link sent from client

// steps
// update the routes in the controller
// configure the Database for the correct format for the userDetails object like (JWT_TOKEN: token, ACCESS_TOKEN=token, 2factor: false)
// 

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.web.cors.CorsConfiguration;
// import org.springframework.web.cors.CorsConfigurationSource;
// import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
        .csrf(csrf -> csrf.disable())
        .cors(cors -> cors.disable())
        .authorizeHttpRequests((authorizeHttpRequests) ->
        authorizeHttpRequests
        .requestMatchers(HttpMethod.POST, "/login").permitAll()
        .requestMatchers(HttpMethod.POST, "/create-account").permitAll()
        .requestMatchers(HttpMethod.GET, "/verify-account").permitAll()
        .requestMatchers(HttpMethod.POST, "/reset-password").hasAnyRole("USER", "ADMIN")
        .requestMatchers(HttpMethod.POST, "/create-product").hasAuthority("create.product")
        .requestMatchers(HttpMethod.PUT, "/update-product").hasAuthority("update.product")
        // for each route set the authorities required and roles. scopes for create account is scopes.create-account
        .anyRequest().authenticated()
        );

    return http.build();
    }
}