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
package com.mhs.authService.common.validation.orchestration;

import com.mhs.authService.common.identifier.matcher.EmailRegexMatcher;
import com.mhs.authService.common.validation.dto.ValidationError;
import com.mhs.authService.common.validation.strategy.email.EmailValidationStrategy;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@RequiredArgsConstructor
class EmailValidationOrchestrator implements UsernameValidationOrchestrator{

    private final EmailRegexMatcher matcher;
	private final List<EmailValidationStrategy> emailValidationStrategies;

	@Override
	public boolean supports(String email) {
		return matcher.determine(email);
	}

	@Override
	public Optional<ValidationError> isValid(String email) {
		return emailValidationStrategies.stream()
				.map(strategy -> strategy.isValid(email))
				.filter(Optional::isPresent)
				.findFirst()
				.orElse(Optional.empty());
	}

}
