package com.mhs.authService.iam.role;

public interface RoleService {

    Role findByName(String name);
    Role findByNameOrCreate(String name);

}
