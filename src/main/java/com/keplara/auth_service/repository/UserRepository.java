package com.keplara.auth_service.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import com.keplara.auth_service.model.mongo.User;

public interface UserRepository extends MongoRepository<User, String> {
    
    @Query("{ 'sessionId' : ?0 }")
    User findBySessionId(String sessionId);
    
    @Query("{ 'userId' : ?0 }")
    User findByUserId(String userId);

    @Query("{ 'username' : ?0 }")
    User findByUsername(String username);

    @Query("{ 'emailAddress' : ?0 }")
    User findByEmailAddress(String emailAddress);
}