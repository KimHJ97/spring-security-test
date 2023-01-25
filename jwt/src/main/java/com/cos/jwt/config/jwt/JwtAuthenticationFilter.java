package com.cos.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 존재
// /login 요청때 username, password를 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter: 로그인 시도중");
		
		// 1. username, password를 받는다.
		try {
			/*
			BufferedReader br = request.getReader();
			String input = null;
			while((input = br.readLine()) != null) {
				System.out.println(input);
			}
			*/
			
			ObjectMapper objectMapper = new ObjectMapper();
			User user = objectMapper.readValue(request.getReader(), User.class);
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// 아래 메소드가 실행될 때 
			// PrincipalDetailsService의 loadUserByUsername() 메소드가 실행된다.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println(principalDetails.getUser().getUsername());
			
			return authentication;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		// 2. 정상인지 검증
		// authenticationManager로 로그인시도를 하면 PrincipalDetailsService가 호출된다.
		// 이때 loadUserByUsername이 실행된다.
		
		// 3. PrincipalDetails를 세션에 담는다. (권한 관리를 위해서)
		
		
		// 4. JWT 토큰을 만들어서 응답한다.
		
		
		return null;
	}

	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 
	// successfulAuthentication 함수가 실행된다.
	// 여기서 JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨!");
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + 60000 * 10))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("cos"));
		
		response.addHeader("Authorization", "Bearer " + jwtToken);
	}
}
