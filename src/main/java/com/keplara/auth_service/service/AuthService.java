package com.keplara.auth_service.service;

import org.springframework.stereotype.Service;

import com.keplara.auth_service.model.IdToken;
import com.keplara.auth_service.model.mongo.Session;
import com.keplara.auth_service.model.mongo.User;
import com.keplara.auth_service.repository.SessionRepository;
import com.keplara.auth_service.repository.UserRepository;
import com.nimbusds.oauth2.sdk.GrantType;

import io.jsonwebtoken.Claims;

import java.util.List;
import java.util.Map;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;


@Service
public class AuthService {

  private final SessionRepository sessionRepository;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public AuthService(SessionRepository sessionRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
      this.sessionRepository = sessionRepository;
      this.userRepository = userRepository;
      this.passwordEncoder = passwordEncoder;
  }

  public RegisterClientResponse registerClient(String clientId, String clientSecret){
    // client can be registerd with they 
    // add to data base
    // create client registration repository
    return new RegisterClientResponse(clientId, clientSecret);
  }
  
  public Boolean createUser(String username, String emailAddress, String password) {
    String hashedPassword = passwordEncoder.encode(password);
    Collection<GrantedAuthority> grants = new ArrayList<>();
    grants.add(new SimpleGrantedAuthority("ROLE_USER"));
    List<String> authorities = new ArrayList<>();
    authorities.add("user.read");
    authorities.add("openid");

    // Save the username, email address, and hashed password to the database
    User user = new User(username, emailAddress, hashedPassword, grants, authorities);
    userRepository.save(user);
    return true;
  }

  public Session authenticate(){
    return new Session();
  }

  public String findUserId(String userName, String email){
    return "";
  }

  public Session getSession(String sessionId){
    return this.sessionRepository.findBySessionId(sessionId);
  }

  public void createSession(Session session){
  }

  public User getUser(String username){
    User foundUserByUsername = this.userRepository.findByUsername(username);
    User foundUserByEmailAddress = this.userRepository.findByEmailAddress(username);

    if (foundUserByUsername != null){
      return foundUserByUsername;
    } else {
      return foundUserByEmailAddress;
    }
  }

  public IdToken createIdToken(Session userSession) throws MalformedURLException {
    return new IdToken(new URL("http://localhost:8080"), userSession.getUserId(), clientId, userSession.getSessionExpirationDateTime(), LocalDateTime.now());
  }

}
