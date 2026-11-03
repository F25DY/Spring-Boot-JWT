package com.jwt.artifactjwt.service;

import java.time.Instant;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service 
public class TokenService {

    private final JwtEncoder jwtEncoder;
    
    public TokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public String issueToken(String username) {


        Instant now = Instant.now();
        
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer("jwtmysql-lab")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(60))
                .subject(username)
                .build();

        JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256).build();
        
        return jwtEncoder
                .encode(JwtEncoderParameters.from(jwsHeader, claims))
                .getTokenValue();
    } 
}
