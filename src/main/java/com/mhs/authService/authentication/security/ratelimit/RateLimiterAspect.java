package com.mhs.authService.authentication.security.ratelimit;

import com.mhs.authService.authentication.security.ratelimit.annotation.RateLimit;
import com.mhs.authService.exception.error.RateLimitExceededException;
import lombok.AllArgsConstructor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import java.time.Duration;

@Aspect
@Component
@AllArgsConstructor
public class RateLimiterAspect {

    private final RedisTemplate<String,String> redisTemplate;
    private final RateLimiterKeyBuilder keyBuilder;

    @Around("@annotation(rateLimit)")
    public Object handleRateLimit(ProceedingJoinPoint joinPoint, RateLimit rateLimit) throws Throwable{

        String key = keyBuilder.buildCompositeKey(rateLimit.identifiers());

        long incrementCount = redisTemplate.opsForValue().increment(key);
        if (incrementCount == 1){
            redisTemplate.expire(key, Duration.ofMinutes(rateLimit.timeFrameInMinutes()));
        }

        if(incrementCount > rateLimit.maxRequests()){
            throw new RateLimitExceededException("error: Too many requests. Please wait before retrying.");
        }
        return joinPoint.proceed();
    }

}
