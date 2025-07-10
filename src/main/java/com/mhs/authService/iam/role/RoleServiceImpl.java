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
package com.mhs.authService.iam.role;

import com.mhs.authService.exception.error.EntityCreationException;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@Service
@RequiredArgsConstructor
class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Override
    public Role findByName(String name) {
        return roleRepository.findByName(name)
                .orElseThrow(() ->
                        new EntityNotFoundException(String.format("error: role with the given name %s does not exists.",name)));
    }

    @Override
    @Transactional
    public Role findByNameOrCreate(String name) {

        return roleRepository.findByName(name).orElseGet(()-> {
            try {
                    Role role = new Role();
                    role.setName(name);
                    return roleRepository.save(role);
                } catch (DataIntegrityViolationException exception) {
                     return roleRepository.findByName(name)
                     .orElseThrow(() -> new EntityCreationException(
                             String.format("error:Failed to create or retrieve role '%s' due to a conflict.", name)));
                    }
        });
    }

}
