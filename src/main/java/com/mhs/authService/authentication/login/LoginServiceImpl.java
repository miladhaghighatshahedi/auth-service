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
package com.mhs.authService.authentication.login;

import com.mhs.authService.authentication.login.dto.LoginRequest;
import com.mhs.authService.authentication.login.dto.LoginResponse;
import com.mhs.authService.authentication.security.fingerprint.RequestFingerprint;
import com.mhs.authService.authentication.security.fingerprint.RequestFingerprintExtractor;
import com.mhs.authService.infrastructure.hash.TokenHashService;
import com.mhs.authService.infrastructure.security.auth.CustomUserDetails;
import com.mhs.authService.token.core.JwtTokenProperties;
import com.mhs.authService.token.core.JwtTokenService;
import com.mhs.authService.token.refresh.RefreshToken;
import com.mhs.authService.token.refresh.RefreshTokenService;
import com.mhs.authService.token.refresh.factory.RefreshTokenFactory;
import com.mhs.authService.user.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("loginService")
@RequiredArgsConstructor
class LoginServiceImpl implements LoginService {

	private final AuthenticationManager authenticationManager;
	private final RequestFingerprintExtractor requestFingerprintExtractor;
	private final JwtTokenService jwtTokenService;
	private final JwtTokenProperties jwtTokenProperties;
	private final RefreshTokenFactory refreshTokenFactory;
	private final RefreshTokenService refreshTokenService;
	private final TransactionTemplate transactionTemplate;
	private final TokenHashService SHA256TokenHash;


	@Override
	public LoginResponse login(LoginRequest loginRequest, HttpServletRequest httpServletRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken( loginRequest.username(), loginRequest.password())
		);

		RequestFingerprint fingerprint = requestFingerprintExtractor.extractFrom(httpServletRequest);

		String accessToken  = jwtTokenService.generateAccessToken(authentication, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());
		String refreshToken = jwtTokenService.generateRefreshToken(authentication, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());
		String hashedRefreshToken = SHA256TokenHash.hashToken(refreshToken);

		CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
		User user = userDetails.getUser();

		RefreshToken refreshTokenEntity = refreshTokenFactory.create(
				user,
				hashedRefreshToken,
				fingerprint.deviceId(),
				fingerprint.userAgent(),
				fingerprint.ipAddress(),
				Instant.now(),
				Instant.now().plus(jwtTokenProperties.getRefreshTokenExpiryHours(), ChronoUnit.HOURS),
				false);

		transactionTemplate.executeWithoutResult(status -> {
			refreshTokenService.saveRefreshToken(user, refreshTokenEntity);
		});

		return new LoginResponse( accessToken,
								  refreshToken,
								  Instant.now().plus(jwtTokenProperties.getAccessTokenExpiryHours(), ChronoUnit.HOURS),
								  loginRequest.username(),
								  new HashSet<>(authentication.getAuthorities()),
								  "User logged successfully.");
	}

}
