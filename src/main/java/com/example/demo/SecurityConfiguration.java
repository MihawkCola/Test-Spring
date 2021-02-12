package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
    PasswordEncoder passwordEncoder;
 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
        .passwordEncoder(passwordEncoder)
        .withUser("shopper").password(passwordEncoder.encode("shopper")).roles("SHOPPER")
        .and()
        .withUser("seller").password(passwordEncoder.encode("seller")).roles("SELLER")
        .and()
        .withUser("support").password(passwordEncoder.encode("support")).roles("SUPPORT");
        //TODO DB einbinden(nicht statisch)
        //TODO DB account erweitern mit adresse
    }
 
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.authorizeRequests()
					.anyRequest().authenticated()
					.and()
					.formLogin()
					.permitAll()
					.and()
					.logout()
					.permitAll();
	}
}
