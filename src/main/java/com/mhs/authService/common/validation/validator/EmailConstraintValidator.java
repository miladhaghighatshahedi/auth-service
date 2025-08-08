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
package com.mhs.authService.common.validation.validator;

import com.mhs.authService.common.identifier.matcher.UsernameTypeMatcher;
import com.mhs.authService.common.validation.annotation.ValidEmail;
import com.mhs.authService.common.validation.dto.ValidationError;
import com.mhs.authService.common.validation.strategy.email.EmailValidationStrategy;
import com.mhs.authService.common.validation.util.EmailValidatorStrategyComponent;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
public class EmailConstraintValidator implements ConstraintValidator<ValidEmail,String> {

	private final UsernameTypeMatcher matcher;
	private final List<EmailValidationStrategy> emailValidationStrategy;
	private final EmailValidatorStrategyComponent emailValidatorStrategyComponent;

	public EmailConstraintValidator(@Qualifier("emailRegexMatcher") UsernameTypeMatcher matcher,
	                                List<EmailValidationStrategy> emailValidationStrategy,
	                                EmailValidatorStrategyComponent emailValidatorStrategyComponent) {
		this.matcher = matcher;
		this.emailValidationStrategy = emailValidationStrategy;
		this.emailValidatorStrategyComponent = emailValidatorStrategyComponent;
	}

	@Override
	public boolean isValid(String email, ConstraintValidatorContext constraintValidatorContext) {

		if(email == null || email.isBlank()){
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate("Email address can not be null or empty.").addConstraintViolation();
			return false;
		}

		if(!matcher.determine(email)){
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate("Invalid email format.").addConstraintViolation();
			return false;
		}

		Optional<ValidationError> validationError = emailValidatorStrategyComponent.validate(email,emailValidationStrategy);

		if(validationError.isPresent()){
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate(validationError.get().message()).addConstraintViolation();
			return false;
		}

		return true;
	}

}
