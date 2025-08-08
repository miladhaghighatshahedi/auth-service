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
package com.mhs.authService.common.bruteforce;

import com.mhs.authService.common.cache.RedisCacheService;
import lombok.RequiredArgsConstructor;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@RequiredArgsConstructor
public class RedisBruteForce implements BruteForce {

    private final RedisCacheService redisCacheService;
    private final BruteForcePolicy policy;

    @Override
    public void onFailure(String identifier) {

        String attemptKey = policy.attemptKeyPrefix() + identifier;
        String lockKey = policy.lockKeyPrefix() + identifier;

        long attempts = redisCacheService.increment(attemptKey);

        if(attempts == 1){
            redisCacheService.expire(attemptKey,Duration.ofMinutes(policy.lockDurationInMinutes()));
        }

        if (attempts >= policy.maxAttempts()){
            Instant unlockTime = Instant.now().plus(Duration.ofMinutes(policy.lockDurationInMinutes()));
            redisCacheService.set(lockKey,unlockTime.toString(),Duration.ofMinutes(policy.lockDurationInMinutes()));
        }

    }

    @Override
    public void onSuccess(String identifier) {
        redisCacheService.delete(policy.attemptKeyPrefix() + identifier);
        redisCacheService.delete(policy.lockKeyPrefix() + identifier);
    }

    @SuppressWarnings("ConstantConditions")
    @Override
    public boolean isBlocked(String identifier) {

        String lockKey = policy.lockKeyPrefix() + identifier;
        Optional<String> unlockTimeString = redisCacheService.get(lockKey);

        if (unlockTimeString.isEmpty()){ return false;}

        Instant unlockTime = Instant.parse(unlockTimeString.get());
        if(Instant.now().isAfter(unlockTime)){
            redisCacheService.delete(lockKey);
            return false;
        }

        return true;
    }

}
