package com.aekus.auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class AuthServiceApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApiApplication.class, args);
	}

}
