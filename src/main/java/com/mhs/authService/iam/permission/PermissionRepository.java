package com.mhs.authService.iam.permission;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
 interface PermissionRepository extends JpaRepository<Permission,Long> {

   Optional<Permission> findByNameAndRoleId(String name, long roleId);

}
