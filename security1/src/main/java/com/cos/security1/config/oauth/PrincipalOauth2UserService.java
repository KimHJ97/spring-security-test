package com.cos.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

// 기본적으로 DefaultOAuth2UserService를 상속받지 않아도 loadUser가 자동으로 동작
// DefaultOAuth2UserService 상속받아 구현함으로써, 자동 로그인 구현과 PrincipalDetails 반환하도록 설정
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Autowired
	private UserRepository userRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

		// ClientRegistration{registrationId='google', clientId='..', clientSecret='..', clientAuthenticationMethod=org.springframework.security.oauth2.core.ClientAuthenticationMethod@4fcef9d3, authorizationGrantType=org.springframework.security.oauth2.core.AuthorizationGrantType@5da5e9f3, redirectUri='{baseUrl}/{action}/oauth2/code/{registrationId}', scopes=[email, profile], providerDetails=org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails@23f4c6d1, clientName='Google'}
		// registrationId로 어떤 OAuth로 로그인했는지 확인 가능
		System.out.println("userRequest: " + userRequest.getClientRegistration());
		// org.springframework.security.oauth2.core.OAuth2AccessToken@176e04c7
		System.out.println("userRequest: " + userRequest.getAccessToken());
		// {sub=고유번호, name=풀네임, given_name=이름, family_name=성, picture=https://lh3.googleusercontent.com/a/AEdFTp7HZmiDvcdA6FbM3VH-fJ8hq1_sYmkDFRarcTvC=s96-c, email=구글이메일@gmail.com, email_verified=true, locale=ko}
		System.out.println("userRequest: " + super.loadUser(userRequest).getAttributes());

		// username = google_고유번호
		// password = "아무값" -> Oauth를 통한 로그인을 하기 때문에, 비밀번호가 사실 필요 없음
		// email = 반환받은 이메일
		// role = ROLE_USER
		// provider = "google"
		// privoderId = "고유번호"

		// 로그인 버튼 클릭 -> OAuth 로그인 창 -> 로그인 완료
		// -> Code를 리턴 -> OAuth-Client 라이브러리가 Code를 통해 AccessToken 요청
		// userRequest 정보 -> loadUser 함수 -> OAuth 제공회사로부터 회원프로필을 받는다.
		OAuth2User oauth2User = super.loadUser(userRequest);

		// 회원가입 진행
		String provider = userRequest.getClientRegistration().getRegistrationId();
		String providerId = oauth2User.getAttribute("sub");
		String username = provider + "_" + providerId;
		String password = bCryptPasswordEncoder.encode("oauth");
		String email = oauth2User.getAttribute("email");
		String role = "ROLE_USER";

		User userEntity = userRepository.findByUsername(username);

		if(userEntity == null) {
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
			
			System.out.println("구글 최초 로그인");
		} else {
			System.out.println("구글 로그인을 이미 한적이 있습니다.");
		}

		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
