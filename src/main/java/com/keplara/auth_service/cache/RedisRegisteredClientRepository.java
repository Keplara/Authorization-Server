package com.keplara.auth_service.cache;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

import io.jsonwebtoken.lang.Arrays;
import java.util.List;

public class RedisRegisteredClientRepository implements RegisteredClientRepository {

    private static final String REGISTERED_CLIENT_PREFIX = "registered_client:";

	@Autowired
	private RedisTemplate<String, RegisteredClient> redisTemplate;
	
    @Autowired
    private ValueOperations<String, RegisteredClient> valueOperations;


    public RedisRegisteredClientRepository(RegisteredClient... registrations) {
        this(Arrays.asList(registrations));        
    }

    public RedisRegisteredClientRepository(List<RegisteredClient> registrations) {
        Assert.notEmpty(registrations, "registrations cannot be empty");
        for (RegisteredClient registration : registrations) {
            Assert.notNull(registration, "registration cannot be null");
            save(registration);
        }
    }

	  @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        valueOperations.set(REGISTERED_CLIENT_PREFIX + registeredClient.getId(), registeredClient);
        valueOperations.set(REGISTERED_CLIENT_PREFIX + registeredClient.getClientId(), registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return valueOperations.get(REGISTERED_CLIENT_PREFIX + id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return valueOperations.get(REGISTERED_CLIENT_PREFIX + clientId);
    }

    private void assertUniqueIdentifiers(RegisteredClient registeredClient) {
        RegisteredClient existingClient = findById(registeredClient.getId());
        if (existingClient != null) {
            throw new IllegalArgumentException("Registered client must be unique. " +
                    "Found duplicate identifier: " + registeredClient.getId());
        }
        existingClient = findByClientId(registeredClient.getClientId());
        if (existingClient != null) {
            throw new IllegalArgumentException("Registered client must be unique. " +
                    "Found duplicate client identifier: " + registeredClient.getClientId());
        }
        // You may need to implement additional logic for checking uniqueness based on client secret
    }
}