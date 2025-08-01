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
package com.mhs.authService.authentication.verification.otp.tracker;

import com.mhs.authService.authentication.verification.otp.SmsOtpVerificationProperties;
import com.mhs.authService.infrastructure.cache.RedisCacheService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import java.time.Duration;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@RequiredArgsConstructor
class RedisCacheSmsOtpAttemptTracker implements SmsOtpAttemptTracker {

	private final RedisCacheService redisCacheService;
	private final SmsOtpVerificationProperties properties;

	@Override
	public void increment(String mobile) {

		String key = properties.getAttemptPrefix() + mobile;
		Long attempt = redisCacheService.increment(key);

		if(attempt != null && attempt == 1){
			redisCacheService.expire(key, Duration.ofMinutes(properties.getAttemptTtl()));
		}

		if(attempt != null && attempt >= properties.getMaxAttempts()){
			redisCacheService.set(properties.getBlockPrefix()+mobile, " BLOCKED", Duration.ofMinutes(properties.getBlockTtl()));
		}

	}

	@Override
	public boolean isBlocked(String mobile) {
		return redisCacheService.exists(properties.getBlockPrefix() + mobile);
	}

	@Override
	public void reset(String mobile) {
		redisCacheService.delete(properties.getAttemptPrefix()+mobile);
		redisCacheService.delete(properties.getBlockPrefix()+mobile);
	}

}
