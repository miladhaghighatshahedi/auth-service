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
package com.mhs.authService.token.refresh;

import com.mhs.authService.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;
import java.time.Instant;
import java.util.UUID;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@Entity
@Table(name = "tbl_refresh_token")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @UuidGenerator(style = UuidGenerator.Style.TIME)
    @Column(name = "token_id",unique = true,updatable = false,nullable = false, columnDefinition = "UUID")
    private UUID id;

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
