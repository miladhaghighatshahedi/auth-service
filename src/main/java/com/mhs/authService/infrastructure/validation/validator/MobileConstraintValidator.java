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
package com.mhs.authService.infrastructure.validation.validator;

import com.mhs.authService.infrastructure.identifier.matcher.MobileRegexMatcher;
import com.mhs.authService.infrastructure.validation.annotation.ValidMobile;
import com.mhs.authService.infrastructure.validation.dto.ValidationError;
import com.mhs.authService.infrastructure.validation.strategy.mobile.MobileValidationStrategy;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@RequiredArgsConstructor
public class MobileConstraintValidator implements ConstraintValidator<ValidMobile,String> {

	private final MobileRegexMatcher matcher;
	private final List<MobileValidationStrategy> mobileValidationStrategy;

	@Override
	public boolean isValid(String mobile, ConstraintValidatorContext constraintValidatorContext) {

		if(mobile == null || mobile.isBlank()){
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate("mobile number can not be null or empty").addConstraintViolation();
			return false;
		}


		if(!matcher.determine(mobile)){
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate("Invalid mobile format.").addConstraintViolation();
			return false;
		}

		Optional<ValidationError> validationError = mobileValidationStrategy.stream()
				.map(strategy -> strategy.isValid(mobile))
				.filter(Optional::isPresent)
				.findFirst()
				.orElse(Optional.empty());

		if(validationError.isPresent()){
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate(validationError.get().message()).addConstraintViolation();
			return false;
		}

		return true;
	}

}
