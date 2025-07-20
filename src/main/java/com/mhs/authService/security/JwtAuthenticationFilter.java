/*
 * Copyright 2025-2026 the original author.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mhs.authService.security;

import com.mhs.authService.token.JwtTokenUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

	private final JwtTokenUtil jwtTokenUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if(header != null && header.startsWith("Bearer ")){
			String rawToken = header.substring(7);

			try{

				Jwt decodedJwt = jwtTokenUtil.validateAccessToken(rawToken);
				Authentication authentication = jwtTokenUtil.buildAuthenticationFromJwt(decodedJwt);
				SecurityContextHolder.getContext().setAuthentication(authentication);

			}catch (BadCredentialsException ex ){
				logger.warn("JWT authentication failed: {}", ex.getMessage());
				SecurityContextHolder.clearContext();
				throw ex;
			}
		}
        filterChain.doFilter(request,response);
	}
}
