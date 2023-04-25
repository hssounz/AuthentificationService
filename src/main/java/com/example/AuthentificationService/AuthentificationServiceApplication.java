package com.example.AuthentificationService;

import com.example.AuthentificationService.sec.entities.AppRole;
import com.example.AuthentificationService.sec.entities.AppUser;
import com.example.AuthentificationService.sec.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class AuthentificationServiceApplication implements CommandLineRunner {

	@Autowired
	AccountService accountService;

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthentificationServiceApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {

		accountService.addNewRole(new AppRole(null, "USER"));
		accountService.addNewRole(new AppRole(null, "ADMIN"));
		accountService.addNewRole(new AppRole(null, "CUSTOMER_MANAGER"));
		accountService.addNewRole(new AppRole(null, "PRODUCT_MANAGER"));
		accountService.addNewRole(new AppRole(null, "BILLS_MANAGER"));

		accountService.addNewUser(new AppUser(null, "user1", "01234567", new ArrayList<>()));
		accountService.addNewUser(new AppUser(null, "admin", "01234567", new ArrayList<>()));
		accountService.addNewUser(new AppUser(null, "user2", "01234567", new ArrayList<>()));
		accountService.addNewUser(new AppUser(null, "user3", "01234567", new ArrayList<>()));
		accountService.addNewUser(new AppUser(null, "user4", "01234567", new ArrayList<>()));

		accountService.addRoleToUser("user1", "USER");
		accountService.addRoleToUser("admin", "ADMIN");
		accountService.addRoleToUser("admin", "USER");
		accountService.addRoleToUser("user2", "USER");
		accountService.addRoleToUser("user2", "CUSTOMER_MANAGER");
		accountService.addRoleToUser("user3", "USER");
		accountService.addRoleToUser("user3", "PRODUCT_MANAGER");
		accountService.addRoleToUser("user4", "USER");
		accountService.addRoleToUser("user4", "BILLS_MANAGER");
	}

}