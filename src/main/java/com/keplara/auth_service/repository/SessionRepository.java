package com.keplara.auth_service.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import com.keplara.auth_service.model.mongo.Session;

public interface SessionRepository extends MongoRepository<Session, String> {
    
    @Query("{ 'sessionId' : ?0 }")
    Session findBySessionId(String sessionId);
    
    @Query("{ 'userId' : ?0 }")
    Session findByUserId(String userId);

}