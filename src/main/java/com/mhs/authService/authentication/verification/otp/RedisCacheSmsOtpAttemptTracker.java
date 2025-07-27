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
package com.mhs.authService.authentication.verification.otp;

import lombok.AllArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import java.time.Duration;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@AllArgsConstructor
class RedisCacheSmsOtpAttemptTracker implements SmsOtpAttemptTracker{

	private final RedisTemplate<String,String> redisTemplate;
	private final SmsOtpVerificationProperties properties;

	@Override
	public void increment(String mobile) {

		String key = properties.getAttemptPrefix() + mobile;
		Long attempt = redisTemplate.opsForValue().increment(key);

		if(attempt != null && attempt == 1){
			redisTemplate.expire(key, Duration.ofMinutes(properties.getAttemptTtl()));
		}

		if(attempt != null && attempt >= properties.getMaxAttempts()){
			redisTemplate.opsForValue().set(properties.getBlockPrefix()+mobile, " BLOCKED", Duration.ofMinutes(properties.getBlockTtl()));
		}

	}

	@Override
	public boolean isBlocked(String mobile) {
		return redisTemplate.hasKey(properties.getBlockPrefix() + mobile);
	}

	@Override
	public void reset(String mobile) {
		redisTemplate.delete(properties.getAttemptPrefix()+mobile);
		redisTemplate.delete(properties.getBlockPrefix()+mobile);
	}
}
