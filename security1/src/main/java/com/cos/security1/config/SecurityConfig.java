package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
			.requestMatchers(PathRequest.toH2Console()).permitAll()
			.antMatchers("/user/**").authenticated()
			.antMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll()
		.and()
			.headers()
			.frameOptions()
			.sameOrigin()
		.and()
			.formLogin()
			.loginPage("/loginForm")
			.loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다. Controller에 직접 만들 필요가 없음
			.defaultSuccessUrl("/")
		.and()
		// 1. 코드받기(인증), 2. 엑세스토큰(권한), 3. 사용자 프로필 정보 가져오기
		// 4-1. 정보를 토대로 회원가입 자동 진행시키는 것도 가능
		// 4-2. (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 -> (vip등급, 일반등급) 등 추가적인 정보 등록이 필요하다.
		// 즉, 추가적인 정보가 필요하다면, 추가적인 입력 화면 후 회원가입
		// 추가적인 정보가 필요없다면, oauth 인증 후 즉시 회원가입
		// 구글 로그인이 완료된 뒤에 엑세스토큰과 사용자 프로필 정보 한번에 받는다.
			.oauth2Login()
			.loginPage("/loginForm")
			.userInfoEndpoint()
				.userService(principalOauth2UserService)
			;
	}
}
