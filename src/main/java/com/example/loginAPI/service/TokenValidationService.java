package com.example.loginAPI.service;

import com.example.loginAPI.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenValidationService {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public Map<String, Object> validateToken(String token) {
        Map<String, Object> validationResult = new HashMap<>();

        try {
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            String username = jwtService.extractUsername(token);

            if (username == null) {
                validationResult.put("valid", false);
                validationResult.put("error", "Invalid token: No username found");
                return validationResult;
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            boolean isValid = jwtService.isTokenValid(token, userDetails);

            if (isValid) {
                validationResult.put("valid", true);
                validationResult.put("username", username);
                validationResult.put("expiresAt", jwtService.extractClaim(token, claims -> claims.getExpiration()));
                validationResult.put("issuedAt", jwtService.extractClaim(token, claims -> claims.getIssuedAt()));
                validationResult.put("message", "Token is valid");
            } else {
                validationResult.put("valid", false);
                validationResult.put("error", "Invalid token");
            }

        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            validationResult.put("valid", false);
            validationResult.put("error", "Token validation failed: " + e.getMessage());
        }

        return validationResult;
    }

    public boolean isTokenValid(String token) {
        try {
            Map<String, Object> validationResult = validateToken(token);
            return (Boolean) validationResult.get("valid");
        } catch (Exception e) {
            return false;
        }
    }
}