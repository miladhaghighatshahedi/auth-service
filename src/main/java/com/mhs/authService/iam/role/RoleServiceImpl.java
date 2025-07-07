package com.mhs.authService.iam.role;

import com.mhs.authService.exception.error.EntityCreationException;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private static final Logger logger = LoggerFactory.getLogger(RoleServiceImpl.class);
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
