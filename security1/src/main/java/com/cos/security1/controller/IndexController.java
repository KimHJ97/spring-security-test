package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;


@Controller
public class IndexController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping({"", "/"})
	public String index() {
		return "index";
	}

	@ResponseBody
	@GetMapping("/user")
	public String user() {
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
