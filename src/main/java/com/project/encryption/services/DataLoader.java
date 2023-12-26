package com.project.encryption.services;

import com.project.encryption.model.ERole;
import com.project.encryption.model.Role;
import com.project.encryption.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;

@Service
public class DataLoader implements ApplicationRunner {

    private final RoleRepository roleRepository;

    @Autowired
    public DataLoader(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        initializeRoles();
    }

    private void initializeRoles() {
//        for (ERole role : ERole.values()) {
//            if (!roleRepository.existsByName(role.name().toString())) {
//                Role newRole = new Role();
//                newRole.setName(ERole.valueOf(role.name().toString()));
//                roleRepository.save(newRole);
//            }
//
//        }

        if (roleRepository.count() == 0) {
            // If not, add them
            Role userRole = new Role();
            userRole.setName(ERole.ROLE_USER);
            roleRepository.save(userRole);

            Role adminRole = new Role();
            adminRole.setName(ERole.ROLE_ADMIN);
            roleRepository.save(adminRole);

            System.out.println("Roles added to the database.");
        } else {
            System.out.println("Roles already exist in the database.");
        }
    }
}
