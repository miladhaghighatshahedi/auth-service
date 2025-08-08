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
package com.mhs.authService.authentication.login.bruteforce;

import com.mhs.authService.common.bruteforce.BruteForce;
import com.mhs.authService.common.bruteforce.BruteForcePolicy;
import com.mhs.authService.common.bruteforce.RedisBruteForce;
import com.mhs.authService.common.cache.RedisCacheService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Milad Haghighat Shahedi
 */

@Configuration
public class BruteForceConfig {

	@Bean("userBruteForce")
	public BruteForce userBruteForce(RedisCacheService redisCacheService, LoginBruteForceProperties properties) {
		BruteForcePolicy userBruteForcePolicy = new BruteForcePolicy(properties.getMaxAttempts(),
				properties.getBanDurationMinutes(),
				properties.getUserAttemptKeyPrefix(),
				properties.getUserBlockKeyPrefix());
		return new RedisBruteForce(redisCacheService, userBruteForcePolicy);
	}

	@Bean("ipBruteForce")
	public BruteForce ipBruteforce(RedisCacheService redisCacheService, LoginBruteForceProperties properties) {
		BruteForcePolicy ipBruteForcePolicy = new BruteForcePolicy(properties.getMaxAttempts(),
				properties.getBanDurationMinutes(),
				properties.getIpAttemptKeyPrefix(),
				properties.getIpBlockKeyPrefix());
		return new RedisBruteForce(redisCacheService, ipBruteForcePolicy);
	}

}
