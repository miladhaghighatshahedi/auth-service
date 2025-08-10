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
package com.mhs.authService.authentication.verification.email.ratelimit;

import com.mhs.authService.authentication.verification.email.exception.EmailTooManyRequestException;
import com.mhs.authService.common.cache.RedisCacheService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("emailResendVerificationRateLimiterService")
@RequiredArgsConstructor
class EmailResendVerificationRateLimiterServiceImpl implements EmailResendVerificationRateLimiterService {

    private final EmailResendVerificationRateLimiterProperties properties;
	private final RedisCacheService redisCacheService;

	@Override
	public void resendVerificationAllowed(String email) {

		String coolDownKey = properties.getEmailCoolDownPrefix() + email;

		if(redisCacheService.exists(coolDownKey)){
			throw new EmailTooManyRequestException("error: email resend temporarily disabled, try in the next few seconds.");
		}

		String key = properties.getEmailCountKeyPrefix() + email;
		Long attempt = redisCacheService.increment(key);

		if(attempt != null && attempt == 1){
			redisCacheService.expire(key, Duration.ofMinutes(properties.getEmailTtl()));
		}

		if(attempt != null && attempt >= properties.getEmailMaxAttempts()){
			throw new EmailTooManyRequestException("error: Too many email resend, please try again later.");
		}

		redisCacheService.set(coolDownKey, "1", Duration.ofSeconds(properties.getEmailBlockTtl()));

	}

}
