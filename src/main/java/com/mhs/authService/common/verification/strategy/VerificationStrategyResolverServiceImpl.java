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
package com.mhs.authService.common.verification.strategy;

import com.mhs.authService.common.verification.dto.VerificationPayload;
import com.mhs.authService.user.enums.UsernameType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("verificationStrategyResolverService")
@RequiredArgsConstructor
class VerificationStrategyResolverServiceImpl implements VerificationStrategyResolverService {

	private final List<VerificationStrategy> strategies;

	public VerificationPayload generatePayLoad(String username, UsernameType usernameType){
		return strategies.stream()
				.filter(strategy -> strategy.supports(usernameType))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException("UsernameType not Supported."))
				.generate(username);
	}

}
