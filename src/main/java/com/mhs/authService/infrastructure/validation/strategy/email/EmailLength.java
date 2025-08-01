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
package com.mhs.authService.infrastructure.validation.strategy.email;

import com.mhs.authService.infrastructure.validation.dto.ValidationError;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@Order(2)
class EmailLength implements EmailValidationStrategy{

	private static final int EMAIL_MIN_LENGTH = 11;
	private static final int EMAIL_MAX_LENGTH = 60;

	@Override
	public Optional<ValidationError> isValid(String email) {
		if(email.length() < EMAIL_MIN_LENGTH || email.length() > EMAIL_MAX_LENGTH){
			return Optional.of(new ValidationError(
					String.format("Email must be between %s and %s characters",EMAIL_MIN_LENGTH,EMAIL_MAX_LENGTH),
                    "USERNAME",
					"EMAIL_INVALID_LENGTH"
					));
		}
		return Optional.empty();
	}

}
