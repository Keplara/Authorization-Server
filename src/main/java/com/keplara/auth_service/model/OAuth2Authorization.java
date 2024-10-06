package com.keplara.auth_service.model;

import java.util.Map;
import java.util.Set;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;

import lombok.Data;

import java.io.Serializable;

@Data
public class OAuth2Authorization implements Serializable {
	private String id;  
	private String registeredClientId;  
	private String principalName;   
	private AuthorizationGrantType authorizationGrantType;  
	private Set<String> authorizedScopes;   
	private Map<Class<? extends OAuth2Token>, Token<?>> tokens; 
	private Map<String, Object> attributes;

}