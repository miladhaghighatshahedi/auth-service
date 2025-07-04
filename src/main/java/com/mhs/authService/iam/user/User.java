package com.mhs.authService.iam.user;

import com.mhs.authService.enums.UsernameType;
import com.mhs.authService.iam.role.Role;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "tbl_credential",uniqueConstraints = {@UniqueConstraint(columnNames = "username")})
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
    private boolean accountNonLocked = true;

    @Column(nullable = false)
    private boolean enabled = true;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_credential_role",
            joinColumns = @JoinColumn(name="credential_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

}
