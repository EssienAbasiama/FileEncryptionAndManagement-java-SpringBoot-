package com.project.encryption.controller;



import com.project.encryption.config.JwtUtils;
import com.project.encryption.payload.AuthRequest;
import com.project.encryption.payload.LoginRequest;
import com.project.encryption.payload.LoginResponse;
import com.project.encryption.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    @Autowired
    private final JwtUtils jwtUtils;

    @Autowired
    private final AuthenticationManager authenticationManager;


    @PostMapping("/register")
    public void createUser(@RequestBody AuthRequest authRequest){
        authService.createUser(authRequest);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticateAndGetToken(@RequestBody LoginRequest authRequest) {
       return ResponseEntity.ok(authService.signin(authRequest));
    }
}
