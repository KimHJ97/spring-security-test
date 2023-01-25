package com.cos.security1.config.oauth.provider;

public enum ProviderType {
	GOOGLE("google"),
	FACEBOOK("facebook"),
	NAVER("naver"),
	KAKAO("kakao"),
	LOCAL("local");

	private String name;

	ProviderType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
