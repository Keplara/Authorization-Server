package com.keplara.auth_service.service;

import org.springframework.stereotype.Service;

import com.keplara.auth_service.model.mongo.Session;
import com.keplara.auth_service.model.mongo.User;
import com.keplara.auth_service.repository.SessionRepository;
import com.keplara.auth_service.repository.UserRepository;

import java.util.List;
import java.util.ArrayList;

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

  public Boolean CreateUser(String username, String emailAddress, String password) {
    String hashedPassword = passwordEncoder.encode(password);
    List<String> authorities = new ArrayList<>();

    // Save the username, email address, and hashed password to the database
    User user = new User(username, emailAddress, hashedPassword, authorities);
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

}
