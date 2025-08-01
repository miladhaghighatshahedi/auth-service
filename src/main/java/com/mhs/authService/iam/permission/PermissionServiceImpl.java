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
package com.mhs.authService.iam.permission;

import com.mhs.authService.iam.permission.exception.PermissionAlreadyExistsException;
import com.mhs.authService.iam.permission.exception.PermissionNotFoundException;
import com.mhs.authService.iam.role.Role;
import com.mhs.authService.iam.role.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("permissionService")
@RequiredArgsConstructor
class PermissionServiceImpl implements PermissionService {

    private final PermissionRepository permissionRepository;
    private final RoleService roleService;

    @Override
    public Permission findByNameAndRoleId(String name, long roleId) {
        return permissionRepository.findByNameAndRoleId(name,roleId)
            .orElseThrow(() -> new PermissionNotFoundException(String.format("error: permission with the give name %s does not exists.",name)));
    }

    @Override
    public Permission findByRoleNameAndPermissionIfNotExistsCreate(String roleName, String permissionName) {

        Role role = roleService.findByNameOrCreate(roleName);
        permissionRepository.findByNameAndRoleId(permissionName, role.getId()).ifPresent(existingPermission -> {
            throw new PermissionAlreadyExistsException(String.format("error: permission %s already exists for the role %s ",permissionName,roleName));
         });

        Permission permission = new Permission();
        permission.setName(permissionName);
        permission.setRole(role);

        return permissionRepository.save(permission);
    }

}
