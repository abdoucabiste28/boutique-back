package com.marketplace.project.Dtos.response;


import com.marketplace.project.models.user.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {

    private Long id;
    private String userName;
    private String email;
    private Role role;

}
