package com.mhs.authService.iam.permission;

import com.mhs.authService.exception.error.DuplicateEntityException;
import com.mhs.authService.iam.role.Role;
import com.mhs.authService.iam.role.RoleService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PermissionServiceImpl implements PermissionService {

    private static final Logger logger = LoggerFactory.getLogger(PermissionServiceImpl.class);

    private final PermissionRepository permissionRepository;
    private final RoleService roleService;

    @Override
    public Permission findByNameAndRoleId(String name, long roleId) {
        return permissionRepository.findByNameAndRoleId(name,roleId)
            .orElseThrow(() -> new EntityNotFoundException(String.format("error: permission with the give name %s does not exists.",name)));
    }

    @Override
    @Transactional
    public Permission findByRoleNameAndPermissionIfNotExistsCreate(String roleName, String permissionName) {

        Role role = roleService.findByNameOrCreate(roleName);
        permissionRepository.findByNameAndRoleId(permissionName, role.getId()).ifPresent(existingPermission -> {
            throw new DuplicateEntityException(String.format("error: permission %s already exists for role %s ",permissionName,roleName));
         });

        Permission permission = new Permission();
        permission.setName(permissionName);
        permission.setRole(role);

        return permissionRepository.save(permission);
    }

}
