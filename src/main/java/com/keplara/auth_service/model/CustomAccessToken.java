package com.keplara.auth_service.configuration.tokens;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomAccessToken implements Authentication {

    private final Object principal; // Typically this should be your user details object
    private final Object credentials; // Typically this can be a password or other credentials
    private Collection<? extends GrantedAuthority> authorities;

    public CustomAccessToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = authorities;
    }
    
    @Override
    public String getName() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getName'");
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getAuthorities'");
    }

    @Override
    public Object getCredentials() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getCredentials'");
    }

    @Override
    public Object getDetails() {
        // TODO Auto-generated method stub
        // this is where the user details are stored
        // id
        // email
        // userName
        // age
        throw new UnsupportedOperationException("Unimplemented method 'getDetails'");
    }

    @Override
    public Object getPrincipal() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getPrincipal'");
    }

    @Override
    public boolean isAuthenticated() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'isAuthenticated'");
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setAuthenticated'");
    }
    
    // Custom method to get username
    public String getUserName() {
        // Replace with actual logic to get the username from your user details object
        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }
        return null;
    }
}
