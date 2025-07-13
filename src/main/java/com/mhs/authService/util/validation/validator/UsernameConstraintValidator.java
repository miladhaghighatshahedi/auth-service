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
package com.mhs.authService.util.validation.validator;

import com.mhs.authService.util.validation.annotation.ValidUsername;
import com.mhs.authService.util.validation.dto.ValidationError;
import com.mhs.authService.util.validation.orchestration.UsernameValidationOrchestrator;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@AllArgsConstructor
public class UsernameConstraintValidator implements ConstraintValidator<ValidUsername,String> {

	private final List<UsernameValidationOrchestrator> usernameValidationOrchestrators;

	@Override
	public boolean isValid(String username, ConstraintValidatorContext constraintValidatorContext) {

		if(username == null || username.isBlank()){
			return false;
		}

		Optional<ValidationError> validationError =usernameValidationOrchestrators.stream()
					.filter(strategy -> strategy.supports(username))
					.findFirst()
					.map(strategy -> strategy.isValid(username))
					.orElse(Optional.of(new ValidationError("Username must be a valid email or phone number.", "USERNAME", "USERNAME_FORMAT_INVALID")));

		if(validationError.isPresent()){
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate(validationError.get().message()).addConstraintViolation();
			return false;
		}
		return true;
	}

}
