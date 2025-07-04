package com.mhs.authService.authentication.security.bruteforce;

public record BruteForcePolicy(int maxAttempts,
                               int lockDurationInMinutes,
                               String attemptKeyPrefix,
                               String lockKeyPrefix){}
