package com.project.encryption.services;


import com.project.encryption.config.AppUserDetails;
import com.project.encryption.config.JwtUtils;
import com.project.encryption.model.AppUser;
import com.project.encryption.model.ERole;
import com.project.encryption.model.Role;
import com.project.encryption.payload.AuthRequest;
import com.project.encryption.payload.LoginRequest;
import com.project.encryption.payload.LoginResponse;
import com.project.encryption.repository.AppUserRepository;
import com.project.encryption.repository.RoleRepository;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final AppUserRepository appUserRepository;

    private final RoleRepository roleRepository;

    @Autowired
    private final PasswordEncoder encoder;

    private RestTemplate restTemplate;

    @Autowired
    private AuthenticationManager authenticationManager;



   private final JwtUtils jwtUtils;




    public void createUser(AuthRequest authRequest){

      if (appUserRepository.existsByUsername(authRequest.getUsername())){
          throw new RuntimeException("Username already exist");
      }
        if (appUserRepository.existsByUsername(authRequest.getEmail())){
            throw new RuntimeException("email already exist");
        }

        AppUser appUser=AppUser.builder()
                               .email(authRequest.getEmail())
                               .username(authRequest.getUsername())
                               .password(encoder.encode(authRequest.getPassword()))
                               .roles(Collections.singleton(roleRepository.findByName(ERole.ROLE_USER).get()))
                               .build();
        appUserRepository.save(appUser);
//        Set<Role> roles = new HashSet<>();
//        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
//                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//        roles.add(userRole);
//
//        AppUser user = new AppUser();
//        user.setEmail(authRequest.getEmail());
//        user.setUsername(authRequest.getUsername());
//        user.setEmail(authRequest.getEmail());
//        user.setPassword(encoder.encode(authRequest.getPassword()));
//        user.setRoles(roles);
//        appUserRepository.save(user);

    }
    public LoginResponse signin(LoginRequest authRequest){
        System.out.println(authRequest);

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        System.out.println(authentication.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        if (authentication.isAuthenticated()) {

            AppUserDetails userDetails = (AppUserDetails) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                                            .map(item -> item.getAuthority())
                                            .collect(Collectors.toList());

            LoginResponse  loginResponse = LoginResponse.builder().username(userDetails.getUsername())
                                            .token(jwtUtils.generateToken(authRequest.getUsername()))
                                            .role(roles)
                                            .build();

            return loginResponse;




        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }
    }



    public LoginResponse loginResponse(LoginRequest loginRequest) {

        AppUser appUser = appUserRepository.findByUsername(loginRequest.getUsername()).get();
        System.out.println(appUser);




            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(appUser.getUsername(), appUser.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateToken(loginRequest.getUsername());

            AppUserDetails userDetails = (AppUserDetails) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                                            .map(item -> item.getAuthority())
                                            .collect(Collectors.toList());


            return LoginResponse.builder()
                                .token(jwt)
                                .username(userDetails.getUsername())
                                .role(roles).build();

    }



}
