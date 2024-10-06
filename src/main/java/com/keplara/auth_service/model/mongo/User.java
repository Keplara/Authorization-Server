package com.keplara.auth_service.model.mongo;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Map;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import lombok.Data;
import java.util.List;

@Document("user")
@Data
public class User implements UserDetails {
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

  private Collection<? extends GrantedAuthority> grants;

  private Boolean expired;
  private Boolean accountLocked;
  private Boolean credentialsExpired;
  private Boolean enabled;

  private String name;
  // user profile endpoint
  private String profile;
  private String picture;
  private LocalDate birthdate;
  private String zone;
  private String local;
  private String phoneNumber;
  private String address;
  private List<String> authorities;
  public User(){}

  public User(String username, String emailAddress, String password, Collection<? extends GrantedAuthority> grants, List<String> authorities){
    this.password = password;
    this.emailAddress = emailAddress;
    this.username = username;
    this.authorities = authorities; 
    this.grants = grants;
    this.expired = false;
    this.accountLocked = false;
    this.credentialsExpired = false;
    this.enabled = true;
  }

  public Map<String, Object> getClaims(){
    return null;
  }
  
  public String getUsernameOrEmailAddress(){
    return emailAddress != null ? emailAddress : username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return !this.expired;
  }

  @Override
  public boolean isAccountNonLocked() {
    return !this.accountLocked;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return !this.credentialsExpired;
  }

  @Override
  public boolean isEnabled() {
   return this.enabled;
  }
  
}