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
package com.mhs.authService.authentication.security.bruteforce;

import lombok.AllArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@AllArgsConstructor
public class RedisBruteForce implements BruteForce {

    private final RedisTemplate<String,String> redisTemplate;
    private final BruteForcePolicy policy;

    @Override
    public void onFailure(String identifier) {

        String attemptKey = policy.attemptKeyPrefix() + identifier;
        String lockKey = policy.lockKeyPrefix() + identifier;

        long attempts = redisTemplate.opsForValue().increment(attemptKey);

        if(attempts == 1){
            redisTemplate.expire(attemptKey, Duration.ofMinutes(policy.lockDurationInMinutes()));
        }

        if (attempts >= policy.maxAttempts()){
            Instant unlockTime = Instant.now().plus(Duration.ofMinutes(policy.lockDurationInMinutes()));
            redisTemplate.opsForValue().set(lockKey,unlockTime.toString(),Duration.ofMinutes(policy.lockDurationInMinutes()));
        }

    }

    @Override
    public void onSuccess(String identifier) {
        redisTemplate.delete(policy.attemptKeyPrefix() + identifier);
        redisTemplate.delete(policy.lockKeyPrefix() + identifier);
    }

    @SuppressWarnings("ConstantConditions")
    @Override
    public boolean isBlocked(String identifier) {
        String lockKey = policy.lockKeyPrefix() + identifier;
        String unlockTimeString = redisTemplate.opsForValue().get(lockKey);

        if (unlockTimeString == null || unlockTimeString.isEmpty() ){ return false;}

        Instant unlockTime = Instant.parse(unlockTimeString);
        if(Instant.now().isAfter(unlockTime)){
            redisTemplate.delete(lockKey);
            return false;
        }
        return true;
    }
}
