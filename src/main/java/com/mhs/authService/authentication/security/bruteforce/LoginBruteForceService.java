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

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

/**
 *
 * @author Milad Haghighat Shahedi
 */

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
