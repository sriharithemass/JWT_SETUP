package com.secure.jwt_setup.services;

import com.secure.jwt_setup.dtos.UserDTO;
import com.secure.jwt_setup.models.Role;
import com.secure.jwt_setup.models.User;

import java.util.List;

public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User findByUsername(String username);

    List<Role> getAllRoles();

    void updatePassword(Long userId, String password);
}
