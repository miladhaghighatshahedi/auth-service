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
import com.mhs.authService.authentication.dto.LogoutResponse;
import com.mhs.authService.authentication.dto.RegistrationResponse;
import com.mhs.authService.authentication.security.fingerprint.AuthenticationRequestFingerprint;
import com.mhs.authService.authentication.security.fingerprint.AuthenticationRequestFingerprintExtractor;
import com.mhs.authService.authentication.validator.CredentialValidationService;
import com.mhs.authService.authentication.verification.VerificationStrategyResolver;
import com.mhs.authService.authentication.verification.dto.VerificationPayload;
import com.mhs.authService.exception.error.RegistrationException;
import com.mhs.authService.iam.role.Role;
import com.mhs.authService.iam.role.RoleService;
import com.mhs.authService.iam.user.User;
import com.mhs.authService.iam.user.UserService;
import com.mhs.authService.iam.user.factory.UserFactory;
import com.mhs.authService.security.CustomUserDetails;
import com.mhs.authService.token.JwtTokenUtil;
import com.mhs.authService.token.dto.RefreshTokenRequest;
import com.mhs.authService.token.model.RefreshToken;
import com.mhs.authService.token.model.RefreshTokenService;
import com.mhs.authService.token.model.factory.RefreshTokenFactory;
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
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;

/**
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
	private final RefreshTokenFactory refreshTokenFactory;
	private final AuthenticationManager authenticationManager;
	private final CredentialValidationService credentialValidationService;
	private final AuthenticationRequestFingerprintExtractor authenticationRequestFingerprint;
	private final TransactionTemplate transactionTemplate;
	private final VerificationStrategyResolver verificationStrategyResolver;

	@Override
	public RegistrationResponse register(AuthenticationRequest authenticationRequest, HttpServletRequest httpServletRequest) {

		credentialValidationService.validate(authenticationRequest);

		String username = authenticationRequest.username();
		String rawPassword = authenticationRequest.password();

		if(userService.existsByUsername(username)){
			throw new RegistrationException("error: username already taken!");
		}

		try {
			return transactionTemplate.execute(status -> {
				try {
					Role roleUser = roleService.findByName("ROLE_USER");
					User user = userFactory.createUser(username, rawPassword, Set.of(roleUser));
					User savedUser = userService.save(user);

					VerificationPayload verificationPayload = verificationStrategyResolver.generatePayLoad(user.getUsername(), user.getUsernameType());


					return new RegistrationResponse(savedUser.getUsername(), "User registered successfully!");
				} catch (DataIntegrityViolationException e) {
					throw new RegistrationException("error: Username already exists. Please choose a different username.");
				} catch (DataAccessException exception) {
					throw new RegistrationException("error: Database error occurred during registration. Please try again later.");
				}
			});



		} catch (TransactionException e) {
			throw new RegistrationException("Error: Unable to register user due to transaction failure.");
		}

	}

	@Override
	public AuthenticationResponse login(AuthenticationRequest authenticationRequest,HttpServletRequest httpServletRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authenticationRequest.username(), authenticationRequest.password())
		);

		AuthenticationRequestFingerprint fingerprint = authenticationRequestFingerprint.extractFrom(httpServletRequest);

		String accessToken  = jwtTokenUtil.generateAccessToken(authentication, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());
		String refreshToken = jwtTokenUtil.generateRefreshToken(authentication, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());
		String hashedRefreshToken = hashService.hashToken(refreshToken);

		CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
		User user = userDetails.getUser();

		RefreshToken refreshTokenEntity = refreshTokenFactory.create(
				user,
				hashedRefreshToken,
				fingerprint.deviceId(),
				fingerprint.userAgent(),
				fingerprint.ipAddress(),
				Instant.now(),
				Instant.now().plus(jwtTokenUtil.getTokenProperties().getRefreshTokenExpiryHours(), ChronoUnit.HOURS),
				false);

		transactionTemplate.executeWithoutResult(status -> {
			refreshTokenService.saveRefreshToken(user, refreshTokenEntity);
		});

		return new AuthenticationResponse(
				accessToken,
				refreshToken,
				Instant.now().plus(jwtTokenUtil.getTokenProperties().getAccessTokenExpiryHours(), ChronoUnit.HOURS),
				authenticationRequest.username(),
				new HashSet<>(authentication.getAuthorities()),
				"User logged successfully.");
	}

	@Override
	public AuthenticationResponse rotate(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {

		AuthenticationRequestFingerprint fingerprint = authenticationRequestFingerprint.extractFrom(httpServletRequest);

		Jwt validatedJWT = jwtTokenUtil.validateRefreshToken(refreshTokenRequest,fingerprint.deviceId(), fingerprint.userAgent(),fingerprint.ipAddress());

		Authentication authentication = jwtTokenUtil.buildAuthenticationFromJwt(validatedJWT);
		String oldHashedRefreshToken = hashService.hashToken(validatedJWT.getTokenValue());

		String accessToken = jwtTokenUtil.generateAccessToken(authentication, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());
		String refreshToken = jwtTokenUtil.generateRefreshToken(authentication, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());
		String newHashedRefreshToken = hashService.hashToken(refreshToken);


		return transactionTemplate.execute(status -> {

			refreshTokenService.revokeToken(hashService.hashToken(oldHashedRefreshToken));
			User user = userService.findByUsername(authentication.getName());
			RefreshToken refreshTokenEntity = refreshTokenFactory.create(
					user,
					newHashedRefreshToken,
					fingerprint.deviceId(),
					fingerprint.userAgent(),
					fingerprint.ipAddress(),
					Instant.now(),
					Instant.now().plus(jwtTokenUtil.getTokenProperties().getRefreshTokenExpiryHours(), ChronoUnit.HOURS),
					false);
			refreshTokenService.saveRefreshToken(user,refreshTokenEntity);

			return new AuthenticationResponse(
					accessToken,
					refreshToken,
					Instant.now().plus(jwtTokenUtil.getTokenProperties().getAccessTokenExpiryHours(), ChronoUnit.HOURS),
					authentication.getName(),
					new HashSet<>(authentication.getAuthorities()),
					"Token rotated successfully."
			);
		});

	}

	@Override
	public LogoutResponse logout(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {

		AuthenticationRequestFingerprint fingerprint = authenticationRequestFingerprint.extractFrom(httpServletRequest);
		String deviceId =fingerprint.deviceId();
		String userAgent = fingerprint.userAgent();
		String ipAddress = fingerprint.ipAddress();

		jwtTokenUtil.validateRefreshToken(refreshTokenRequest,deviceId,userAgent,ipAddress);

		String hashedToken = hashService.hashToken(refreshTokenRequest.refreshToken());

		transactionTemplate.executeWithoutResult(status -> {
			refreshTokenService.revokeToken(hashedToken);
		});

		return new LogoutResponse("User logout successfully.");
	}

}
