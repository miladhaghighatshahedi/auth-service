package com.mhs.authService.iam.role;

import com.mhs.authService.iam.permission.Permission;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "tbl_role",uniqueConstraints = {@UniqueConstraint(columnNames = "name")})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id",unique = true,updatable = false,nullable = false)
    private Long id;

    @Column(name = "name",nullable = false,unique = true,length = 50)
    private String name;

    @OneToMany(mappedBy = "role",cascade = CascadeType.ALL,orphanRemoval = true,fetch = FetchType.LAZY)
    private Set<Permission> permissions = new HashSet<>();

    public void addPermission(Permission permission){
        permissions.add(permission);
        permission.setRole(this);
    }

    public void removePermission(Permission permission){
        permissions.remove(permission);
        permission.setRole(null);
    }


}
