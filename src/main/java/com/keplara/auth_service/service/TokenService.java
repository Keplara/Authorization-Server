package com.keplara.auth_service.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.keplara.auth_service.configuration.exceptions.AuthApiException;
import com.keplara.auth_service.factory.TokenFactory;
import com.keplara.auth_service.model.jwt.CreateAccountJwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Service
public class TokenService {
    private TokenFactory tokenBuilder;

    public TokenService(TokenFactory tokenBuilder) {
        this.tokenBuilder = tokenBuilder;
    }

    public String createAccountToken(String emailAddress, String password, String username){
        Claims claims = Jwts.claims()
        .add("emailAddress", emailAddress)
        .add("password", password)
        .add("username", username).build();
        // have a JWT class that takes claims and expiration time
        return tokenBuilder.createToken(30, claims, true);
    }

    public CreateAccountJwt parseAccountToken(String token) throws AuthApiException {
        CreateAccountJwt createAccountJwt = new CreateAccountJwt();
        Claims claims =  tokenBuilder.getClaims(token);
        createAccountJwt.setEmailAddress((String) claims.get("emailAddress"));
        createAccountJwt.setUsername((String) claims.get("username"));
        createAccountJwt.setPassword((String) claims.get("password"));
        return createAccountJwt;
    }

}
