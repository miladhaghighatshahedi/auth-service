package com.mhs.authService.authentication.security.bruteforce;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RegisterBruteForceService {

    private final BruteForce ipBruteForce;

    public RegisterBruteForceService(RedisTemplate<String,String> redisTemplate,
                                     RegisterBruteForceProperties properties) {

        this.ipBruteForce = new RedisBruteForce(
                redisTemplate,
                new BruteForcePolicy( properties.getMaxAttempts(),
                                                properties.getBanDurationMinutes(),
                                                properties.getIpAttemptKeyPrefix(),
                                                properties.getIpBlockKeyPrefix()));
    }

    public void onFailure(String ip){
        ipBruteForce.onFailure(ip);
    }

    public void onSuccess(String ip){
        ipBruteForce.onSuccess(ip);
    }

    public boolean isBlocked(String ip){
        return ipBruteForce.isBlocked(ip);
    }

}
