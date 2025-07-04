package com.mhs.authService.authentication.security.bruteforce;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class LoginBruteForceService {

    private final BruteForce userBruteforce;
    private final BruteForce ipBruteForce;

    public LoginBruteForceService(RedisTemplate<String,String> redisTemplate,
                                  LoginBruteForceProperties properties) {

        this.userBruteforce = new RedisBruteForce(
                redisTemplate,
                new BruteForcePolicy( properties.getMaxAttempts(),
                                                properties.getBanDurationMinutes(),
                                                properties.getUserAttemptKeyPrefix(),
                                                properties.getUserBlockKeyPrefix()));

        this.ipBruteForce = new RedisBruteForce(
                redisTemplate,
                new BruteForcePolicy( properties.getMaxAttempts(),
                                                properties.getBanDurationMinutes(),
                                                properties.getIpAttemptKeyPrefix(),
                                                properties.getIpBlockKeyPrefix()));
    }

    public void onFailure(String ip, String username){
        ipBruteForce.onFailure(ip);
        userBruteforce.onFailure(username);
    }

    public void onSuccess(String ip,String username){
        ipBruteForce.onSuccess(ip);
        userBruteforce.onSuccess(username);
    }

    public boolean isBlocked(String ip,String username){
        return ipBruteForce.isBlocked(ip) || userBruteforce.isBlocked(username);
    }

}
