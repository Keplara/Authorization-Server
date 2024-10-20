package com.keplara.auth_service.service;

import org.springframework.stereotype.Service;

import com.keplara.auth_service.model.mongo.User;
import com.keplara.auth_service.repository.UserRepository;

import java.util.List;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
public class AuthService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  public Boolean createUser(String username, String emailAddress, String password) {
    String hashedPassword = passwordEncoder.encode(password);
    Collection<GrantedAuthority> authorities = List.of(
        new SimpleGrantedAuthority("user.write"),
        new SimpleGrantedAuthority("user.read"),
        new SimpleGrantedAuthority("user.create"),
        new SimpleGrantedAuthority("user.delete"));

    User user = new User(username, emailAddress, hashedPassword, authorities);
    userRepository.save(user);
    return true;
  }

  public String findUserId(String userName, String email) {
    return "";
  }

  public User getUser(String username) {
    User foundUserByUsername = this.userRepository.findByUsername(username);
    User foundUserByEmailAddress = this.userRepository.findByEmailAddress(username);

    if (foundUserByUsername != null) {
      return foundUserByUsername;
    } else {
      return foundUserByEmailAddress;
    }
  }

}
