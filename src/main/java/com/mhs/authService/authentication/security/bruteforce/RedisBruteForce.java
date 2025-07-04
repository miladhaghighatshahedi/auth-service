package com.mhs.authService.authentication.security.bruteforce;

import lombok.AllArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;

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
