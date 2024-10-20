package com.keplara.auth_service.configuration.cache;

import java.time.Duration;

import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;


@Configuration
@EnableCaching
public class RedisConfig {

    @Bean
    public JedisConnectionFactory jedisConnectionFactory() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
        config.setHostName("localhost"); 
        config.setPort(6379);
		config.setDatabase(0);
		config.setUsername("grant");
        config.setPassword("grant");
        return new JedisConnectionFactory(config);
    }
    
  
    @Bean
    public RedisTemplate<String, RegisteredClient> redisTemplate(JedisConnectionFactory jedisConnectionFactory) {
        RedisTemplate<String, RegisteredClient> template = new RedisTemplate<>();
        template.setConnectionFactory(jedisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        return template;
    }
	
	@Bean
	public RedisCacheManagerBuilderCustomizer myRedisCacheManagerBuilderCustomizer() {
		return (builder) -> builder.withCacheConfiguration("userId", RedisCacheConfiguration.defaultCacheConfig().entryTtl(Duration.ofDays(5)))
				.withCacheConfiguration("authorizationCode", RedisCacheConfiguration.defaultCacheConfig().entryTtl(Duration.ofMinutes(1)));
	}
}