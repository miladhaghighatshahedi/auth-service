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
package com.mhs.authService.authentication.validator;

import com.mhs.authService.authentication.dto.AuthenticationRequest;
import com.mhs.authService.exception.error.CredentialValidationException;
import com.mhs.authService.util.validation.dto.ValidationError;
import com.mhs.authService.util.validation.validator.PasswordValidator;
import com.mhs.authService.util.validation.validator.UsernameValidator;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Milad Haghighat Shahedi
 */

@Service
@AllArgsConstructor
class CredentialValidationServiceImpl implements CredentialValidationService{

	private final UsernameValidator usernameValidator;
	private final PasswordValidator passwordValidator;

	public void validate(AuthenticationRequest authenticationRequest){
		List<ValidationError> errors = new ArrayList<>();

		usernameValidator.validate(authenticationRequest.username()).ifPresent(errors::add);
		passwordValidator.validate(authenticationRequest.password()).ifPresent(errors::add);

		if(!errors.isEmpty()){
		  throw new CredentialValidationException(errors);
		}
	}

}
