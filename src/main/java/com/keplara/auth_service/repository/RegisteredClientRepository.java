package com.keplara.auth_service.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public interface RegisteredClientRepository extends MongoRepository<RegisteredClient, String> {
    @Query("{ 'clientId' : ?0 }")
    RegisteredClient findByClientId(String clientId);
}