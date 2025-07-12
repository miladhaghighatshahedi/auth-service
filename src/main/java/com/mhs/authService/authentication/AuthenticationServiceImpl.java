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
package com.mhs.authService.authentication;

import com.mhs.authService.authentication.dto.AuthenticationRequest;
import com.mhs.authService.authentication.dto.AuthenticationResponse;
import com.mhs.authService.authentication.dto.RegistrationResponse;
import com.mhs.authService.authentication.resolver.IpAddressResolverService;
import com.mhs.authService.exception.error.RegistrationException;
import com.mhs.authService.iam.role.RoleService;
import com.mhs.authService.iam.user.User;
import com.mhs.authService.iam.user.UserService;
import com.mhs.authService.iam.user.factory.UserFactory;
import com.mhs.authService.token.JwtTokenUtil;
import com.mhs.authService.token.dto.RefreshTokenRequest;
import com.mhs.authService.token.model.RefreshTokenService;
import com.mhs.authService.util.hash.HashService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@Service
@AllArgsConstructor
class AuthenticationServiceImpl implements AuthenticationService{

	private final UserService userService;
	private final UserFactory userFactory;
	private final RoleService roleService;
	private final HashService hashService;
	private final JwtTokenUtil jwtTokenUtil;
	private final RefreshTokenService refreshTokenService;
	private final AuthenticationManager authenticationManager;
    private final IpAddressResolverService ipAddressResolverService;

	@Override
	@Transactional
	public RegistrationResponse register(AuthenticationRequest authenticationRequest, HttpServletRequest httpServletRequest) {

		String username = authenticationRequest.getUsername();
		String rawPassword = authenticationRequest.getPassword();

		if(userService.existsByUsername(username)){
			throw new DataIntegrityViolationException("error: username already taken!");
		}

		try{

			User user = userFactory.createUser(username, rawPassword, Set.of(roleService.findByName("ROLE_USER")));
			User savedUser = userService.save(user);

			return new RegistrationResponse(savedUser.getUsername(), "User registered successfully!");

		}catch (DataAccessException exception){
			throw new RegistrationException("error: Database error occurred during registration. Please try again later.");
		}catch (Exception exception) {
			throw new RegistrationException("error: Registration failed due to an internal error.");
		}

	}

	@Override
	@Transactional
	public AuthenticationResponse login(AuthenticationRequest authenticationRequest,HttpServletRequest httpServletRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
		);

		String ipAddress = ipAddressResolverService.detect(httpServletRequest);
		String deviceId  = httpServletRequest.getHeader("X-Device-Id");
		String userAgent = httpServletRequest.getHeader("User-Agent");

		String accessToken  = jwtTokenUtil.generateAccessToken(authentication, deviceId, userAgent, ipAddress);
		String refreshToken = jwtTokenUtil.generateRefreshToken(authentication, deviceId, userAgent, ipAddress);

		String hashedToken = hashService.hashToken(refreshToken);

		refreshTokenService.saveRefreshToken(
				authentication.getName(),
				hashedToken,
				deviceId,
				userAgent,
				ipAddress,
				Instant.now(),
				Instant.now().plus(jwtTokenUtil.getTokenProperties().getRefreshTokenExpiryHours(), ChronoUnit.HOURS));

		return new AuthenticationResponse(
				accessToken,
				refreshToken,
				Instant.now().plus(jwtTokenUtil.getTokenProperties().getAccessTokenExpiryHours(), ChronoUnit.HOURS),
				authenticationRequest.getUsername(),
				new HashSet<>(authentication.getAuthorities()),
				"User logged successfully.");
	}

	@Override
	@Transactional
	public AuthenticationResponse rotate(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {

		String ipAddress = ipAddressResolverService.detect(httpServletRequest);
		String userAgent = httpServletRequest.getHeader("User-Agent");
		String deviceId = httpServletRequest.getHeader("X-Device-Id");

		Jwt validatedJWT = jwtTokenUtil.validateRefreshToken(refreshTokenRequest,deviceId,userAgent,ipAddress);
		Authentication authentication = jwtTokenUtil.buildAuthenticationFromJwt(validatedJWT);

		String oldTokenString = validatedJWT.getTokenValue();

		String accessToken = jwtTokenUtil.generateAccessToken(authentication, deviceId, userAgent, ipAddress);
		String refreshToken = jwtTokenUtil.generateRefreshToken(authentication, deviceId, userAgent, ipAddress);

		refreshTokenService.revokeToken(hashService.hashToken(oldTokenString));

		refreshTokenService.saveRefreshToken(
				authentication.getName(),
				hashService.hashToken(refreshToken),
				deviceId,
				userAgent,
				ipAddress,
				Instant.now(),
				Instant.now().plus(jwtTokenUtil.getTokenProperties().getRefreshTokenExpiryHours(),ChronoUnit.HOURS)
		);

		return new AuthenticationResponse(
				accessToken,
				refreshToken,
				Instant.now().plus(jwtTokenUtil.getTokenProperties().getAccessTokenExpiryHours(), ChronoUnit.HOURS),
				authentication.getName(),
				new HashSet<>(authentication.getAuthorities()),
				"Token rotated successfully."
		);
	}

	@Override
	@Transactional
	public AuthenticationResponse logout(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {

		String ipAddress = ipAddressResolverService.detect(httpServletRequest);
		String userAgent = httpServletRequest.getHeader("User-Agent");
		String deviceId  = httpServletRequest.getHeader("X-Device-Id");

		System.out.println(refreshTokenRequest.refreshToken());

		jwtTokenUtil.validateRefreshToken(refreshTokenRequest,deviceId,userAgent,ipAddress);

		String hashedToken = hashService.hashToken(refreshTokenRequest.refreshToken());

		refreshTokenService.revokeToken(hashedToken);

		return new AuthenticationResponse(
				null,
				null,
				null,
				null,
				null,
				"User logout successfully.");
	}

}
