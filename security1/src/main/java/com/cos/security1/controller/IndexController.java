package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;


@Controller
public class IndexController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@ResponseBody
	@GetMapping("/test/login")
	public String testLogin(
			Authentication authentication,
			@AuthenticationPrincipal UserDetails userDetails,
			@AuthenticationPrincipal PrincipalDetails userDetails2) {
		System.out.println("=======================");
		// 다운캐스팅하여 가져오기
		PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
		System.out.println("authentication: " + principalDetails.getUser());
		System.out.println("=======================");
		// @AuthenticationPrincipal 어노테이션을 통해 가져오기
		System.out.println("userDetails: " + userDetails.getUsername());
		System.out.println("userDetails: " + userDetails2.getUser());
		System.out.println("=======================");
		
		return "세션 정보 확인하기";
	}

	@ResponseBody
	@GetMapping("/test/oauth/login")
	public String testOAuthLogin(
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oauth) {
		System.out.println("=======================");
		// 다운캐스팅하여 가져오기
		OAuth2User oauth2User = (OAuth2User)authentication.getPrincipal();
		System.out.println("authentication: " + oauth2User.getAttributes());
		System.out.println("=======================");
		// @AuthenticationPrincipal 어노테이션을 통해 가져오기
		System.out.println("oauth2User: " + oauth.getAttributes());
		System.out.println("=======================");
		
		return "OAuth 세션 정보 확인하기";
	}

	@GetMapping({"", "/"})
	public String index() {
		return "index";
	}

	@ResponseBody
	@GetMapping("/user")
	public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails: " + principalDetails.getUser());
		return "user";
	}

	@ResponseBody
	@GetMapping("/admin")
	public String admin() {
		return "admin";
	}

	@ResponseBody
	@GetMapping("/manager")
	public String manager() {
		return "manager";
	}

	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}

	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}

	@PostMapping("/join")
	public String join(User user) {
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);

		userRepository.save(user);

		return "redirect:/loginForm";
	}

	// 권한명만을 설정
	@Secured("ROLE_ADMIN")
	@ResponseBody
	@GetMapping("/info")
	public String info() {
		return "개인정보";
	}

	// 해당 어노테이션은 권한명만을 쓸 수 없고, hasRole을 이용
	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
	@ResponseBody
	@GetMapping("/data")
	public String data() {
		return "데이터정보";
	}
}
