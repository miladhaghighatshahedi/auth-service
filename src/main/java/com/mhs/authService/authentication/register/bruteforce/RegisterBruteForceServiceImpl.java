package com.mhs.authService.authentication.register.bruteforce;

import com.mhs.authService.common.bruteforce.BruteForce;
import com.mhs.authService.common.bruteforce.BruteForcePolicy;
import com.mhs.authService.common.bruteforce.RedisBruteForce;
import com.mhs.authService.common.cache.RedisCacheService;
import org.springframework.stereotype.Service;

@Service("registerBruteForceService")
public class RegisterBruteForceServiceImpl implements RegisterBruteForceService{

    private final BruteForce ipBruteForce;

    public RegisterBruteForceServiceImpl(RedisCacheService redisCacheService,
                                         RegisterBruteForceProperties properties) {

        this.ipBruteForce = new RedisBruteForce( redisCacheService,
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
