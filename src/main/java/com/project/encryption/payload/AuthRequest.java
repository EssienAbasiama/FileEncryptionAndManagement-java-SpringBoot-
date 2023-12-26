package com.project.encryption.payload;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class AuthRequest {

    private String email;
    private String username;

    private String password;

}
