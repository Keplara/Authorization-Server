package com.keplara.auth_service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

import com.keplara.auth_service.repository.UserRepository;

// remove auto configuration to have more security. We can look into it later.
@SpringBootApplication(exclude = { SecurityAutoConfiguration.class })
@EnableMongoRepositories
public class AuthApplication {

	@Autowired
  	UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}
	
}
