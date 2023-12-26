package com.project.encryption.payload;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@AllArgsConstructor
@Data
public class LoginResponse {

    private String token;
    private List<String> role;
    private String username;

}
