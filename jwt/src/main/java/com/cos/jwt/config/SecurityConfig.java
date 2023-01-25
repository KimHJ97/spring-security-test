package com.cos.jwt.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@SuppressWarnings("deprecation")
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	private final UserRepository userRepository;

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
		
		http.csrf().disable();
		http
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
			.headers()
			.frameOptions()
			.sameOrigin()
		.and()
			.addFilter(corsFilter) // @CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
			.addFilter(new JwtAuthenticationFilter(authenticationManager()))
			.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
			.formLogin().disable()
			.httpBasic().disable()
			.authorizeRequests()
			.requestMatchers(PathRequest.toH2Console()).permitAll()
			.antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll();
		
	}
}
