package com.cos.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

// 시큐리티가 filter를 가지고 있는데, BasicAuthenticationFilter 라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음
// 만약, 권한이나 인증이 필요한 주소가 아니라면 해당 필터를 타지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	// 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터가 타게 된다.
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("인증이나 권한이 필요한 주소에 요청됨!");
		
		String jwtHeader = request.getHeader("Authorization");
		System.out.println(jwtHeader);
		
		// Header가 있는지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		// JWT 토큰을 검증해서 정상적인 사용자인지 확인
		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
		System.out.println(jwtToken);
		
		String username = JWT.require(Algorithm.HMAC512("cos"))
				.build()
				.verify(jwtToken)
				.getClaim("username")
				.asString();
		System.out.println(username);
		
		// 서명이 정상적으로 됨
		if(username != null) {
			User userEntity = userRepository.findByUsername(username);
			System.out.println(userEntity.getId());
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			// 로그인을 통해 만드는 것이 아니기 때문에 비밀번호는 그냥 null로 해도된다.
			// JWT 토큰 서명을 통해서 서명이 정상이면 authentication 객체를 만들어준다.
			Authentication authentication =
					new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			
			// 강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
	}
}
