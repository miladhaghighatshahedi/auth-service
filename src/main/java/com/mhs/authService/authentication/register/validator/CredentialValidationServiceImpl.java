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
package com.mhs.authService.authentication.register.validator;

import com.mhs.authService.authentication.register.dto.RegisterRequest;
import com.mhs.authService.authentication.register.exception.CredentialValidationException;
import com.mhs.authService.common.validation.dto.ValidationError;
import com.mhs.authService.common.validation.validator.password.PasswordValidatorService;
import com.mhs.authService.common.validation.validator.username.UsernameValidatorService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("credentialValidationService")
@RequiredArgsConstructor
class CredentialValidationServiceImpl implements CredentialValidationService{

	private final UsernameValidatorService usernameValidatorService;
	private final PasswordValidatorService passwordValidatorService;

	public void validate(RegisterRequest registerRequest){
		List<ValidationError> errors = new ArrayList<>();

		usernameValidatorService.validate(registerRequest.username()).ifPresent(errors::add);
		passwordValidatorService.validate(registerRequest.password()).ifPresent(errors::add);

		if(!errors.isEmpty()){
		  throw new CredentialValidationException(errors);
		}
	}

}
