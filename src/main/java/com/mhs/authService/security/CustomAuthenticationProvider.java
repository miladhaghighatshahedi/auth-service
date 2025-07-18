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

import com.mhs.authService.authentication.resolver.HttpContextIpAddressResolver;
import com.mhs.authService.authentication.security.bruteforce.LoginBruteForceService;
import com.mhs.authService.util.encoding.CustomArgon2PasswordEncoder;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@Component
@AllArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final CustomUserDetailsService userDetailsService;
	private final CustomArgon2PasswordEncoder passwordEncoder;
	private final HttpContextIpAddressResolver httpContextIpAddressResolver;
	private final LoginBruteForceService loginBruteForceService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		String rawPassword = authentication.getCredentials().toString();
		String ip = httpContextIpAddressResolver.detect();

		if(loginBruteForceService.isBlocked(ip,username)){
			throw new LockedException("error: Too many failed login attempts. Please try again later.");
		}

		try{
			CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(username);
			String encryptedPassword = userDetails.getPassword();

			if(!passwordEncoder.matches(rawPassword,encryptedPassword)){
				loginBruteForceService.onFailure(ip,username);
				throw new BadCredentialsException("error: Invalid Credentials.");
			}

			if(!userDetails.isEnabled()){
				throw new BadCredentialsException("error: Invalid Credentials.");
			}

			if(!userDetails.isAccountNonLocked()){
				throw new BadCredentialsException("error: Invalid Credentials.");
			}

			loginBruteForceService.onSuccess(ip,username);

			return new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

		}catch (UsernameNotFoundException exception){
			loginBruteForceService.onFailure(ip,username);
			throw new BadCredentialsException("error: Invalid Credentials.");
		}

	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
