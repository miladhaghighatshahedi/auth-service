package com.mhs.authService.token.model;

import com.mhs.authService.iam.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;
import java.time.Instant;

@Entity
@Table(name = "tbl_refresh_token")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @UuidGenerator(style = UuidGenerator.Style.TIME)
    @Column(name = "tokene_id",unique = true,updatable = false,nullable = false)
    private long id;

    @Column(name = "hashed_token",nullable = false, unique = true, length = 512)
    private String hashedToken;

    @Column(name = "device_id",nullable = false)
    private String deviceId;

    @Column(name = "user_agent",nullable = false)
    private String userAgent;

    @Column(name = "ip_address",nullable = false)
    private String ipAddress;

    @Column(name = "issued_date",nullable = false)
    private Instant issuedDate;

    @Column(name = "expiry_date",nullable = false)
    private Instant expiryDate;

    @Column(name = "revoked",nullable = false)
    private boolean revoked;

    @ManyToOne(fetch = FetchType.LAZY,optional = false)
    @JoinColumn(name = "user_id")
    private User user;

}
