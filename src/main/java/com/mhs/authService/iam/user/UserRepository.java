package com.mhs.authService.iam.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
interface UserRepository extends JpaRepository<User, UUID> {

    @Query("""
            SELECT u FROM User u
            LEFT JOIN FETCH u.roles r
            WHERE u.username = :username
            """)
    Optional<User> findByUsername(@Param("username") String username);

}
