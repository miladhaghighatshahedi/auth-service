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
@Order(1)
class EmailBlank implements EmailValidationStrategy{

	@Override
	public Optional<ValidationError> isValid(String email) {
		if(email == null || email.isBlank()){
			return Optional.of(new ValidationError("Email can not be null or blank!","EMAIL","USERNAME_BLANK"));
		}
		return Optional.empty();
	}

}
