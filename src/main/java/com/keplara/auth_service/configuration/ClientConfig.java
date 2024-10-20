package com.keplara.auth_service.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import java.util.UUID;


@Configuration
public class ClientConfig {

	@Value("${client_registration_secret}")
	private String secret;

    @Bean
	public RedisRegisteredClientRepository registeredClientRepository(RedisTemplate<String, RegisteredClient> redisTemplate) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

		RegisteredClient registrarClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("registrar-client")
				.clientSecret("{bcrypt}"+passwordEncoder.encode(secret))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)	
				.scope("client.create")	
				.scope("client.read")	
				.build();

		return new RedisRegisteredClientRepository(redisTemplate, registrarClient);
	}

}
