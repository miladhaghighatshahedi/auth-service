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
package com.mhs.authService.setup;

import com.mhs.authService.authentication.register.RegisterService;
import com.mhs.authService.authentication.register.dto.RegisterRequest;
import com.mhs.authService.iam.permission.PermissionService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author Milad Haghighat Shahedi
 */

//@Component
@RequiredArgsConstructor
public class defaultUserSetup implements ApplicationRunner {

	private final PermissionService permissionService;
	private final RegisterService registerService;

	@Override
	@Transactional
	public void run(ApplicationArguments args){
		createPermissionsAndRoles();
		createUsers();
	}

	private void createPermissionAndRoleIfNotExists(String permissionName,String roleName){
		permissionService.findByRoleNameAndPermissionIfNotExistsCreate(roleName, permissionName);
	}

	private void createPermissionsAndRoles(){
		createPermissionAndRoleIfNotExists("PERMIT_ADD_PRODUCT", "ROLE_USER");
		createPermissionAndRoleIfNotExists("PERMIT_UPDATE_PRODUCT", "ROLE_USER");
		createPermissionAndRoleIfNotExists("PERMIT_DISABLE_PRODUCT", "ROLE_USER");
		createPermissionAndRoleIfNotExists("PERMIT_VIEW_PRODUCT", "ROLE_USER");
		createPermissionAndRoleIfNotExists("PERMIT_MANAGE_ADMIN", "ROLE_ADMIN");
	}


	private void createUsers(){
		MockHttpServletRequest mockRequest = new MockHttpServletRequest();
		mockRequest.setRemoteAddr("127.0.0.1"); // Simulate IP
		registerUser("user@gmail.com","#cvdCVD321",mockRequest);
	}

	private void registerUser(String username,String password,HttpServletRequest httpServletRequest){
		RegisterRequest registerRequest = new RegisterRequest(username,password);
		registerService.register(registerRequest,httpServletRequest);
	}

}
