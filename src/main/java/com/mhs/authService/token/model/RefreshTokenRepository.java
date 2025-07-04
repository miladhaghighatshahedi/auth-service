package com.mhs.authService.token.model;

import com.mhs.authService.iam.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long> {

    Optional<RefreshToken> findByHashedToken(String token);
    List<RefreshToken> findAllByUserAndDeviceId(User user, String deviceId);

}
