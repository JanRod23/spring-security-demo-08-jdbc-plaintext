package com.luv2code.springsecurity.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		// Add our users for in memory authentication
		UserBuilder users = User.withDefaultPasswordEncoder();
		
		auth.inMemoryAuthentication()
			.withUser(users.username("john").password("test123").roles("EMPLOYEE"))
			.withUser(users.username("mary").password("test123").roles("EMPLOYEE", "MANAGER"))
			.withUser(users.username("susan").password("test123").roles("EMPLOYEE", "ADMIN"));
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
				/** .anyRequest().authenticated() // Any request coming in must be authenticated **/
				.antMatchers("/").hasRole("EMPLOYEE") // for the "/" path, user must be EMPLOYEE (configs are in configure method)
				.antMatchers("/leaders/**").hasRole("MANAGER") // the ** means any sub directory of the "/leaders" pathsystems/**
				.antMatchers("/systems/**").hasRole("ADMIN")
			.and()
			.formLogin() // Customize the login form
				.loginPage("/showMyLoginPage") // Mapping for login page
				.loginProcessingUrl("/authenticateTheUser") // Where the user login form gets processed
				.permitAll() // Allows everyone to see the login page (you dont have to be logged in to see it)
			.and()
			.logout().permitAll() // Adds log out functionallity 
			.and()
			.exceptionHandling().accessDeniedPage("/access-denied");
		
	}
	
}
