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
package com.mhs.authService.user;

import com.mhs.authService.iam.role.Role;
import com.mhs.authService.user.enums.UsernameType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * @author Milad Haghighat Shahedi
 */

@Entity
@Table(name = "tbl_credential",uniqueConstraints = {@UniqueConstraint(columnNames = "username")})
@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class User {

    @Id
    @UuidGenerator(style = UuidGenerator.Style.TIME)
    @Column(name = "id",unique = true,updatable = false,nullable = false,columnDefinition = "UUID")
    private UUID auth_id;

    @Column(name = "username",unique = true,updatable = false, nullable = false, length = 60)
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(name = "username_type", nullable = false, length = 20)
    private UsernameType usernameType;

    @Column(name = "password", nullable = false,columnDefinition = "TEXT")
    private String password;

    @Column(name = "joined_date",updatable = false, nullable = false)
    private LocalDateTime joinedDate;

    @Column(nullable = false)
    private boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_credential_role",
            joinColumns = @JoinColumn(name="credential_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    public void addRole(Role role) {
        this.roles.add(role);
    }

}
