package com.luv2code.springsecurity.demo.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
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
	
	// Reference to our security data source
	@Autowired
	private DataSource securityDataSource;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		// Use JDBC authentication
		auth.jdbcAuthentication().dataSource(securityDataSource);
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
