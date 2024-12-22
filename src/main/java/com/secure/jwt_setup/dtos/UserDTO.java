package com.secure.jwt_setup.dtos;

import com.secure.jwt_setup.models.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private Long userId;
    private String userName;
    private String email;
    private Role role;
    private LocalDateTime createdDate;
    private LocalDateTime updatedDate;
}
