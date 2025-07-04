package com.mhs.authService.authentication.security.bruteforce;

public interface BruteForce {

    void onFailure(String identifier);
    void onSuccess(String identifier);
    boolean isBlocked(String identifier);

}
