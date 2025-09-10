package com.example.loginAPI.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/protected")
@Tag(name = "Protected Resources", description = "Protected endpoints that require valid JWT")
@SecurityRequirement(name = "bearerAuth")
public class ProtectedController {

    @GetMapping("/user-info")
    @Operation(summary = "Get user info", description = "Get information about the authenticated user")
    public ResponseEntity<Map<String, Object>> getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", authentication.getName());
        userInfo.put("authorities", authentication.getAuthorities());
        userInfo.put("authenticated", authentication.isAuthenticated());

        return ResponseEntity.ok(userInfo);
    }

    @GetMapping("/health")
    @Operation(summary = "Protected health check", description = "Health check endpoint that requires authentication")
    public ResponseEntity<Map<String, String>> protectedHealth() {
        return ResponseEntity.ok(Map.of("status", "OK", "message", "Protected endpoint is accessible"));
    }
}
