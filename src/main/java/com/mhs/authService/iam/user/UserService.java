package com.mhs.authService.iam.user;

public interface UserService {

    User findByUsername(String username);
    User save(User user);
    boolean existsByUsername(String username);

}
