package com.keplara.auth_service.model.mongo;

import java.util.ArrayList;
import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Document("user")
@Data
public class User {
  @Id
  private String userId;

  private String password;

  private String email;

  private String userName;

  // TODO
  private Boolean authenticatorEnabled;

  // Twillo
  private Boolean twoFactorEnabled;

  private List<String> authorities = new ArrayList<>();

  public User(){}

  public User(String password, String email, String userName, List<String> roles){
    this.password = password;
    this.email = email;
    this.userName = userName;
    this.authorities = authorities; 
  }
  
}