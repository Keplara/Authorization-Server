package com.keplara.auth_service.service;

import org.springframework.stereotype.Service;

import com.keplara.auth_service.model.mongo.Session;
import com.keplara.auth_service.model.mongo.User;
import com.keplara.auth_service.repository.SessionRepository;
import com.keplara.auth_service.repository.UserRepository;

@Service
public class AuthService {

    // private final UserRepository userRepository;
  private final SessionRepository sessionRepository;
  private final UserRepository userRepository;


  public AuthService(SessionRepository sessionRepository, UserRepository userRepository) {
      // this.userRepository = userRepository;
      this.sessionRepository = sessionRepository;
      this.userRepository = userRepository;
  }

  public Session authenticate(){
    // if session exist and is not expired -5 minutes then send session back auth complete
    // if session exist and session is not expired but password is supplied send session back auth complete
    // if session does not exist or is expired and password is supplied then login check password match use bycrypt to check password in db
    // if session does not exist and password is not supplied return 403
    return new Session();
  }

  public String findUserId(String userName, String email){
      // if username match then return userId;
      // if email match return userId;
      // if none match return null;   
    return "";
  }

  public Session getSession(String sessionId){
    return this.sessionRepository.findBySessionId(sessionId);
  }

  public void createSession(Session session){
      // create session token and assign in
  }

  // takes username or email
  public User getUser(String username){
    User foundUserByUsername = this.userRepository.findByUsername(username);
    if (foundUserByUsername != null){
      return foundUserByUsername;
    } else {
      return this.userRepository.findByEmailAddress(username);
    }
  }
}
