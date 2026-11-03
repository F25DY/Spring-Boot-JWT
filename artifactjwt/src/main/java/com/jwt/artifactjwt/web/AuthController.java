package com.jwt.artifactjwt.web;


import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.artifactjwt.model.AppUser;
import com.jwt.artifactjwt.repository.UserRepository;
import com.jwt.artifactjwt.service.TokenService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController @RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager auth;
    private final TokenService tokenService;
    
    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager auth,
            TokenService tokenService) {
        this.repo = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auth = auth;
        this.tokenService = tokenService;
    }

    public record Credentials ( @NotBlank String username, @NotBlank String password) {}
    public record Registration ( @NotBlank @Size(min=3, max=100) String username, @NotBlank @Size(min=8) String password) {}

    @PostMapping("/register")
    public ResponseEntity <?> register (@Valid @RequestBody Registration input) {
        
        if (repo.existsByUsername(input.username)) return ResponseEntity.status(409).body(Map.of("error", "Usuario Existente"));
        
        repo.save(new AppUser(input.username, passwordEncoder.encode(input.password)));
        return ResponseEntity.status(201).body(Map.of("message", "Usuario creado exitosamente"));
    }
    
    @PostMapping("/token")
    public Map <String,String> token(@Valid @RequestBody Credentials input) {
        
        auth.authenticate(new UsernamePasswordAuthenticationToken(input.username(), input.password()));
        return Map.of("access_token", tokenService.issueToken(input.username()), "token_type", "Bearer");
    }
    
}
