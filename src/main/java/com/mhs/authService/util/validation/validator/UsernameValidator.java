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

import com.mhs.authService.util.validation.dto.ValidationError;
import com.mhs.authService.util.validation.orchestration.UsernameValidationOrchestrator;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@AllArgsConstructor
public class UsernameValidator {

	private final List<UsernameValidationOrchestrator> usernameValidationStrategies;

	public Optional<ValidationError> validate(String username){

		if(username == null || username.isBlank()){
			return Optional.of(new ValidationError("Username can not be null or blank!", "USERNAME", "USERNAME_BLANK"));
		}

		return usernameValidationStrategies.stream()
				.filter(strategy -> strategy.supports(username))
				.findFirst()
				.map(strategy -> strategy.isValid(username))
				.orElse(Optional.of(new ValidationError("Username must be a valid email or phone number.", "USERNAME", "USERNAME_FORMAT_INVALID")));
	}

}
