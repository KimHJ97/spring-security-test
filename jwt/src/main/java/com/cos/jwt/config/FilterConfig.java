package com.cos.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import com.cos.jwt.filter.MyFilter3;

@Configuration
public class FilterConfig {

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public FilterRegistrationBean<MyFilter1> filter1() {
		FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
		bean.addUrlPatterns("/*");
		bean.setOrder(0);
		return bean;
	}

	@Bean
	public FilterRegistrationBean<MyFilter2> filter2() {
		FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
		bean.addUrlPatterns("/*");
		bean.setOrder(0);
		return bean;
	}

}
