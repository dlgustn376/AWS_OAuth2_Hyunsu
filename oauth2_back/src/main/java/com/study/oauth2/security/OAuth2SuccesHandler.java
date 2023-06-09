package com.study.oauth2.security;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.study.oauth2.entity.User;
import com.study.oauth2.repository.UserRepository;
import com.study.oauth2.security.jwt.JwtTokenProvider;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OAuth2SuccesHandler extends SimpleUrlAuthenticationSuccessHandler{
	private final UserRepository userRepository;
	private final JwtTokenProvider jwtTokenProvider;
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
		String email = oAuth2User.getAttribute("email");
		String provider = oAuth2User.getAttribute("provider");
		User userEntity = userRepository.findUserByEmail(email);
		
		if(userEntity == null) {
			String registerToken = jwtTokenProvider.generateOAuth2RegisterToken(authentication);
			String name = oAuth2User.getAttribute("name");
			response
			.sendRedirect(
					"http://localhost:3000/auth/oauth2/register" 
					+ "?registerToken=" + registerToken 
					+ "&email=" + email 
					+"&name=" + URLEncoder.encode(name, "UTF-8")
					+"&provider=" + provider
					);
		}else {
			//http://localhost:3000/auth/oauth2/register?registerToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJPQXV0aDJSZWdpc3RlciIsImVtYWlsIjoiZGxndXN0bjM3NjhAZ21haWwuY29tIiwiZXhwIjoxNjgzNjk5NzU5fQ.nSNnkIbMFH1441kp5dMENQbVVLfB0hFSt1wRX-zxvcA
			//&email=dlgustn3768@gmail.com
			//&name=%EC%9D%B4%ED%98%84%EC%88%98
		}
		
//		System.out.println((OAuth2User)authentication.getPrincipal());
	}
}
