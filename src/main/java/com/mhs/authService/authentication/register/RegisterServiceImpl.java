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
package com.mhs.authService.authentication.register;

import com.mhs.authService.authentication.register.dto.RegisterRequest;
import com.mhs.authService.authentication.register.dto.RegisterResponse;
import com.mhs.authService.authentication.register.exception.RegistrationException;
import com.mhs.authService.authentication.register.validator.CredentialValidationService;
import com.mhs.authService.authentication.register.bruteforce.RegisterBruteForceService;
import com.mhs.authService.infrastructure.verification.dto.VerificationPayload;
import com.mhs.authService.infrastructure.verification.strategy.VerificationStrategyResolverService;
import com.mhs.authService.iam.role.Role;
import com.mhs.authService.iam.role.RoleService;
import com.mhs.authService.infrastructure.ip.IpAddressResolverService;
import com.mhs.authService.user.User;
import com.mhs.authService.user.UserService;
import com.mhs.authService.user.factory.UserFactory;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;
import java.util.Set;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("registerService")
@RequiredArgsConstructor
public class RegisterServiceImpl implements RegisterService{

	private final UserService userService;
	private final RoleService roleService;
	private final UserFactory userFactory;
	private final TransactionTemplate transactionTemplate;
	private final VerificationStrategyResolverService verificationStrategyResolver;
	private final CredentialValidationService credentialValidationService;
	private final RegisterBruteForceService registerBruteForceService;
	private final IpAddressResolverService ipAddressResolverService;

	@Override
	public RegisterResponse register(RegisterRequest registerRequest, HttpServletRequest httpServletRequest) {

		credentialValidationService.validate(registerRequest);

		String username = registerRequest.username();
		String rawPassword = registerRequest.password();
		String ip = ipAddressResolverService.detect(httpServletRequest);

		if(registerBruteForceService.isBlocked(ip)){
			throw new LockedException("error: Too many failed register attempts. Please try again later.");
		}

		if(userService.existsByUsername(username)){
			registerBruteForceService.onFailure(ip);
			throw new RegistrationException("error: username already taken!");
		}

		try {
			return transactionTemplate.execute(status -> {
				try {
					Role roleUser = roleService.findByName("ROLE_USER");
					User user = userFactory.createUser(username, rawPassword, Set.of(roleUser));
					User savedUser = userService.save(user);

					VerificationPayload verificationPayload = verificationStrategyResolver.generatePayLoad(user.getUsername(), user.getUsernameType());

					System.out.println(verificationPayload.payload());

                    registerBruteForceService.onSuccess(ip);

					return new RegisterResponse(savedUser.getUsername(), "User registered successfully!");
				} catch (DataIntegrityViolationException e) {
					registerBruteForceService.onFailure(ip);
					throw new RegistrationException("error: Username already exists. Please choose a different username.");
				} catch (DataAccessException exception) {
					registerBruteForceService.onFailure(ip);
					throw new RegistrationException("error: Database error occurred during registration. Please try again later.");
				}
			});

		} catch (TransactionException e) {
			registerBruteForceService.onFailure(ip);
			throw new RegistrationException("Error: Unable to register user due to transaction failure.");
		}

	}

}
