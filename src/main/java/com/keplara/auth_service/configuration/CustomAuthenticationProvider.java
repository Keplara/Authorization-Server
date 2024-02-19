package com.keplara.auth_service.configuration;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.keplara.auth_service.configuration.tokens.CustomAccessToken;
import com.keplara.auth_service.model.mongo.User;
import com.keplara.auth_service.service.AuthService;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final AuthService authService;

    public CustomAuthenticationProvider(AuthService authService) {
        this.authService = authService;
    }
    // global authetnication for every requet for jwt token session
    // oauth 2 will be a filter
    // sso will be another filter
    // 2factor is another filter


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {        
        //token
        // do nothing for now.
        String sessionToken = authentication.getPrincipal().toString();
        // CustomAccessToken accessToken = authentication.getCredentials();

        // User userDetails = authService.getSession(token);

        // check if session is valid 
        // check if accessToken is valid
        // check what granted authorities are given with the access token and compare them with the request access scopes
        
        // deny access or return redirect to login if token is expired.
        // remove session from database
        
        // if (userDetails == null) {
        //     throw new UsernameNotFoundException("User not found");
        // }

        // // You might want to perform additional checks on the token here

        // // Create a fully authenticated Authentication object
        // Authentication authenticated = new CustomAccessToken(
        //         userDetails, token, userDetails.getAuthorities());
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'supports'");
    }
}
// security context is holder for information related to security
// can provide other security information is centralized for spring security
// request interceptor security at end
// security context can give us the username of the user
// thread local allows you to store data in the thread. request is served by a single thread and safely store data in the thred (t1) | (t2)
// at the end clear context is called clearing the data in the thread
// log4j not log through the entire application just in a specific place.

//GET MAPPING (Authentication authentication){ authentication.getName() // provides the user that is authenticated}

//set url of the oauth app in the spring properties file
