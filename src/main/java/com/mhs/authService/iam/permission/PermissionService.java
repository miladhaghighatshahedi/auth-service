package com.mhs.authService.iam.permission;

public interface PermissionService {
    Permission findByNameAndRoleId(String name, long roleId);
    Permission findByRoleNameAndPermissionIfNotExistsCreate(String roleName, String permissionName);

}
