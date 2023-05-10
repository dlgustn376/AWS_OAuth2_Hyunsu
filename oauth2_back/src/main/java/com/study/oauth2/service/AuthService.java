package com.study.oauth2.service;

import java.util.Collections;
import java.util.Map;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.study.oauth2.dto.auth.OAuth2RegisterReqDto;
import com.study.oauth2.entity.Authority;
import com.study.oauth2.entity.User;
import com.study.oauth2.repository.UserRepository;
import com.study.oauth2.security.OAuth2Attribute;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	
	private final UserRepository userRepository;
	
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		
		OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		OAuth2Attribute oAuth2Attribute = OAuth2Attribute.of(registrationId, oAuth2User.getAttributes());
		Map<String, Object> attributes = oAuth2Attribute.convertToMap();
		
		return new DefaultOAuth2User(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")), attributes, "email");
	}
	
	public int oauth2Register(OAuth2RegisterReqDto oauth2RegisterReqDto) {
		User userEntity = oauth2RegisterReqDto.toEntity();
		
		userRepository.saveUser(userEntity);
		return userRepository.saveAuthority(
			Authority.builder()
				.userId(userEntity.getUserId())
				.roleId(1)
				.build()
		);
		 
	}
}