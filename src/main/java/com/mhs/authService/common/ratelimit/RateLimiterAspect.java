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
package com.mhs.authService.common.ratelimit;

import com.mhs.authService.common.cache.RedisCacheService;
import com.mhs.authService.common.ratelimit.annotation.RateLimit;
import com.mhs.authService.common.ratelimit.exception.RateLimitExceededException;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * @author Milad Haghighat Shahedi
 */

@Aspect
@Component
@RequiredArgsConstructor
class RateLimiterAspect {

    private final RedisCacheService redisCacheService;
    private final RateLimiterKeyBuilder keyBuilder;

    @Around("@annotation(rateLimit)")
    public Object handleRateLimit(ProceedingJoinPoint joinPoint, RateLimit rateLimit) throws Throwable{

        String identifier = keyBuilder.buildCompositeKey(rateLimit.identifiers());

        String redisKey = rateLimit.key() + identifier;

        long incrementCount = redisCacheService.increment(redisKey);

        if (incrementCount == 1){
            redisCacheService.expire(redisKey,Duration.ofMinutes(rateLimit.timeFrameInMinutes()));
        }

        if(incrementCount > rateLimit.maxRequests()){
            throw new RateLimitExceededException("error: Too many requests. Please wait before retrying.");
        }
        return joinPoint.proceed();
    }

}
