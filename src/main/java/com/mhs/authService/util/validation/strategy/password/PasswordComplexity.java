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
package com.mhs.authService.util.validation.strategy.password;

import com.mhs.authService.util.validation.dto.ValidationError;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@Order(3)
public class PasswordComplexity implements PasswordValidationStrategy{

	private static final Pattern PASSWORD_COMPLEXITY =
			Pattern.compile("^(?=.*[0-9])(?=.*[!@#$%^&*]).{8,}$",Pattern.CASE_INSENSITIVE);

	@Override
	public Optional<ValidationError> isValid(String password) {
		if(!PASSWORD_COMPLEXITY.matcher(password).matches()){
			return Optional.of(new ValidationError("Password must contain at least one number and one special character!","PASSWORD","PASSWORD_COMPLEXITY"));
		}
		return Optional.empty();
	}

}
