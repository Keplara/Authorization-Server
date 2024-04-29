package com.keplara.auth_service.model.mongo;

import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Document("user")
@Data
public class User {
  @Id
  private String userId;

  private String password;

  @Indexed(unique = true)
  private String emailAddress;

  @Indexed(unique = true)
  private String username;

  // TODO
  private Boolean authenticatorEnabled;

  // TODO With Twillo
  private Boolean twoFactorEnabled;

  private List<String> authorities;

  public User(){}

  public User(String username, String emailAddress, String password, List<String> authorities){
    this.password = password;
    this.emailAddress = emailAddress;
    this.username = username;
    this.authorities = authorities; 
  }
  
}