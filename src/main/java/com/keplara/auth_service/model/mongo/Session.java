package com.keplara.auth_service.model.mongo;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;

import lombok.Data;


@Document("session")
@Data
public class Session {
  @Id
  private String sessionId;

  private String userId;

  private LocalDateTime sessionStartDateTime;

  private LocalDateTime sessionExpirationDateTime;

  public Session(){}

  public Session(String id, String userId, LocalDateTime sessionStartDateTime, LocalDateTime sessionExpirationDateTime ) {
    this.sessionId = id;
    this.userId = userId;
    this.sessionStartDateTime = sessionStartDateTime;
    this.sessionExpirationDateTime = sessionExpirationDateTime;
  }

  public Session(String userId) {
    this.userId = userId;
    this.sessionStartDateTime = LocalDateTime.now();
    this.sessionExpirationDateTime =  this.sessionStartDateTime.plusHours(4);
  }
} 