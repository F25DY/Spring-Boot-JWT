package com.jwt.artifactjwt.web;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class SecuredController {

    @GetMapping("/api/secured")
    public Map<String, String> secured(Authentication auth) {
        return Map.of("message", "Acceso autorizado", "username", auth.getName());
    }
}
