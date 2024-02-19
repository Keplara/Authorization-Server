package com.keplara.auth_service.model.mongo;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

import com.mongodb.lang.Nullable;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Document("session")
@NoArgsConstructor
@Data
public class Session {
  @Id
  private String sessionId;

  @NonNull
  private String userId;

  @Nullable
  private LocalDateTime sessionStartDateTime;

  @Nullable
  private LocalDateTime sessionExpirationDateTime;
  
  public Session(String id, String userId,
   LocalDateTime sessionStartDateTime, LocalDateTime sessionExpirationDateTime ) {
    this.sessionId = id;
    this.userId = userId;
    this.sessionStartDateTime = sessionStartDateTime;
    this.sessionExpirationDateTime = sessionExpirationDateTime;
  }

  public Session(String id, String userId) {
    this.sessionId = id;
    this.userId = userId;
    this.sessionStartDateTime = LocalDateTime.now();
    this.sessionExpirationDateTime =  this.sessionStartDateTime.plusHours(4);
  }
} 