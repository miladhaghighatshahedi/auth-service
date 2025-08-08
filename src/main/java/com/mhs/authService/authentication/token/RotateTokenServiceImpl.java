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
package com.mhs.authService.authentication.token;

import com.mhs.authService.authentication.token.dto.RotateTokenRequest;
import com.mhs.authService.authentication.token.dto.RotateTokenResponse;
import com.mhs.authService.common.fingerprint.RequestFingerprint;
import com.mhs.authService.common.fingerprint.RequestFingerprintExtractor;
import com.mhs.authService.common.hash.TokenHashService;
import com.mhs.authService.token.core.JwtTokenProperties;
import com.mhs.authService.token.core.JwtTokenService;
import com.mhs.authService.token.refresh.RefreshToken;
import com.mhs.authService.token.refresh.RefreshTokenService;
import com.mhs.authService.token.refresh.factory.RefreshTokenFactory;
import com.mhs.authService.user.User;
import com.mhs.authService.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("rotateTokenService")
@RequiredArgsConstructor
class RotateTokenServiceImpl implements RotateTokenService{

	private final UserService userService;
	private final TokenHashService SHA256TokenHash;
	private final JwtTokenService jwtTokenService;
	private final JwtTokenProperties jwtTokenProperties;
	private final RefreshTokenService refreshTokenService;
	private final RefreshTokenFactory refreshTokenFactory;
	private final RequestFingerprintExtractor authenticationRequestFingerprint;
	private final TransactionTemplate transactionTemplate;

	@Override
	public RotateTokenResponse rotate(RotateTokenRequest rotateTokenRequest, HttpServletRequest httpServletRequest) {

		RequestFingerprint fingerprint = authenticationRequestFingerprint.extractFrom(httpServletRequest);

		Jwt validatedJWT = jwtTokenService.validateRefreshToken(rotateTokenRequest,fingerprint.deviceId(), fingerprint.userAgent(),fingerprint.ipAddress());

		Authentication authentication = jwtTokenService.buildAuthenticationFromJwt(validatedJWT);
		String oldHashedRefreshToken = SHA256TokenHash.hashToken(validatedJWT.getTokenValue());

		String accessToken = jwtTokenService.generateAccessToken(authentication, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());
		String refreshToken = jwtTokenService.generateRefreshToken(authentication, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());
		String newHashedRefreshToken = SHA256TokenHash.hashToken(refreshToken);


		return transactionTemplate.execute(status -> {

			refreshTokenService.revokeToken(SHA256TokenHash.hashToken(oldHashedRefreshToken));
			User user = userService.findByUsername(authentication.getName());
			RefreshToken refreshTokenEntity = refreshTokenFactory.create( user,
																		  newHashedRefreshToken,
																		  fingerprint.deviceId(),
																		  fingerprint.userAgent(),
																		  fingerprint.ipAddress(),
																		  Instant.now(),
																		  Instant.now().plus(jwtTokenProperties.getRefreshTokenExpiryHours(), ChronoUnit.HOURS),
																		  false);
			refreshTokenService.saveRefreshToken(user,refreshTokenEntity);

			return new RotateTokenResponse( accessToken,
											refreshToken,
											Instant.now().plus(jwtTokenProperties.getAccessTokenExpiryHours(), ChronoUnit.HOURS),
											authentication.getName(),
											new HashSet<>(authentication.getAuthorities()),
											"Token rotated successfully.");
		});

	}
}
