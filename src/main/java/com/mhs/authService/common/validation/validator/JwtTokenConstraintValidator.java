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

import com.mhs.authService.common.validation.annotation.ValidJwtToken;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;

/**
 * @author Milad Haghighat Shahedi
 */

@RequiredArgsConstructor
public class JwtTokenConstraintValidator implements ConstraintValidator<ValidJwtToken,String> {

	@Override
	public boolean isValid(String token, ConstraintValidatorContext constraintValidatorContext) {

		if (token == null || token.isBlank()) {
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate("jwt token can not be null or empty.").addConstraintViolation();
			return false;
		}

		if (!token.matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")) {
			constraintValidatorContext.disableDefaultConstraintViolation();
			constraintValidatorContext.buildConstraintViolationWithTemplate("Invalid JWT token format.").addConstraintViolation();
			return false;
		}

		return true;
	}

}
