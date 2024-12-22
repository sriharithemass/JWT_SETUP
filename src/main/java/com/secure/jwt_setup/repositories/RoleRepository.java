package com.secure.jwt_setup.repositories;

import com.secure.jwt_setup.models.AppRole;
import com.secure.jwt_setup.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);

}