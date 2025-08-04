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
package com.mhs.authService.infrastructure.cache;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import java.time.Duration;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("redisCacheService")
@RequiredArgsConstructor
class RedisCacheServiceImpl implements RedisCacheService{

	private final RedisTemplate<String,String> redisTemplate;

	@Override
	public void set(String key, String value, Duration ttl) {
		redisTemplate.opsForValue().set(key,value,ttl);
	}

	@Override
	public Optional<String> get(String key) {
		return Optional.of(redisTemplate.opsForValue().get(key));
	}

	@Override
	public void delete(String key) {
		redisTemplate.delete(key);
	}

	@Override
	public boolean exists(String key) {
		return redisTemplate.hasKey(key);
	}

	@Override
	public Long increment(String key) {
		return redisTemplate.opsForValue().increment(key);
	}

	@Override
	public void expire(String key, Duration ttl) {
		redisTemplate.expire(key,ttl);
	}

}
