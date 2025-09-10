package com.example.loginAPI.controller;
import com.example.loginAPI.service.TokenValidationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Token Validation", description = "JWT token validation endpoints")
@SecurityRequirement(name = "bearerAuth")
public class TokenValidationController {

    private final TokenValidationService tokenValidationService;

    @PostMapping("/validate")
    @Operation(summary = "Validate JWT token", description = "Validate a JWT token and return validation details")
    @ApiResponse(responseCode = "200", description = "Token validation completed")
    public ResponseEntity<Map<String, Object>> validateToken(
            @RequestHeader("Authorization") String authorizationHeader
    ) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(Map.of(
                    "valid", false,
                    "error", "Authorization header must start with 'Bearer '"
            ));
        }

        Map<String, Object> validationResult = tokenValidationService.validateToken(authorizationHeader);
        return ResponseEntity.ok(validationResult);
    }

    @GetMapping("/check")
    @Operation(summary = "Check token validity", description = "Simple endpoint to check if token is valid")
    @ApiResponse(responseCode = "200", description = "Token check completed")
    public ResponseEntity<Map<String, Object>> checkTokenValidity(
            @RequestHeader("Authorization") String authorizationHeader
    ) {
        boolean isValid = tokenValidationService.isTokenValid(authorizationHeader);
        return ResponseEntity.ok(Map.of("valid", isValid));
    }
}