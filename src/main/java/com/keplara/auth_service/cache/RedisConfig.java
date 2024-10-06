package com.keplara.auth_service.configuration;

import java.time.Duration;

import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;

@Configuration
@EnableCaching
public class RedisConfig {

	@Bean
	JedisConnectionFactory jedisConnectionFactory() {
		return new JedisConnectionFactory();
	}

	@Bean
	public RedisCacheManagerBuilderCustomizer myRedisCacheManagerBuilderCustomizer() {
		return (builder) -> builder.withCacheConfiguration("userId", RedisCacheConfiguration.defaultCacheConfig().entryTtl(Duration.ofDays(5)))
				.withCacheConfiguration("authorizationCode", RedisCacheConfiguration.defaultCacheConfig().entryTtl(Duration.ofMinutes(1)));
	}
}