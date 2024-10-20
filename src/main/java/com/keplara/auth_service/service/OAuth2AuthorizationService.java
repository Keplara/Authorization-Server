
// store tokens in reddis 
// package com.keplara.auth_service.service;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
// import org.springframework.stereotype.Service;
// import org.springframework.util.Assert;

// import com.keplara.auth_service.model.OAuth2Authorization;
// import com.keplara.auth_service.repository.OAuth2AuthorizationRepository;
// import java.util.List;

// @Service
// public class OAuth2AuthorizationService {

//     @Autowired
//     private OAuth2AuthorizationRepository authorizationRepository;

//     public void save(OAuth2Authorization authorization) {
//         Assert.notNull(authorization, "Authorization must not be null");
//         authorizationRepository.save(authorization);
//     }

//     public void remove(OAuth2Authorization authorization) {
//         Assert.notNull(authorization, "Authorization must not be null");
//         authorizationRepository.delete(authorization);
//     }

//     public OAuth2Authorization findById(String id) {
//         Assert.hasText(id, "ID must not be null or empty");
//         return authorizationRepository.findById(id).orElse(null);
//     }

//     public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
//         Assert.hasText(token, "token cannot be empty");
//         if (tokenType == null) {
//             List<OAuth2Authorization> authorizations = authorizationRepository.findByToken(token);
//             return authorizations.isEmpty() ? null : authorizations.get(0);
//         } else {
//             return authorizationRepository.findByTokenAndTokenType(token, tokenType);
//         }
//     }
    
// }
