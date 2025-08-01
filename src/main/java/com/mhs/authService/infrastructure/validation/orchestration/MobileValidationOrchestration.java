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
package com.mhs.authService.infrastructure.validation.orchestration;

import com.mhs.authService.infrastructure.identifier.matcher.MobileRegexMatcher;
import com.mhs.authService.infrastructure.validation.dto.ValidationError;
import com.mhs.authService.infrastructure.validation.strategy.mobile.MobileValidationStrategy;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@RequiredArgsConstructor
class MobileValidationOrchestration implements UsernameValidationOrchestrator{

	private final MobileRegexMatcher matcher;
	private final List<MobileValidationStrategy> mobileValidationStrategies;

	@Override
	public boolean supports(String mobile) {
		return matcher.determine(mobile);
	}

	@Override
	public Optional<ValidationError> isValid(String mobile) {
		return mobileValidationStrategies.stream()
				.map(strategy -> strategy.isValid(mobile))
				.filter(Optional::isPresent)
				.findFirst()
				.orElse(Optional.empty());
	}

}
