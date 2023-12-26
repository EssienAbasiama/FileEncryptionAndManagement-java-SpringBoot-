package com.project.encryption.payload;


import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class CreateUserChat {

   // private String email;
    private String username;

    private String secret;

}
