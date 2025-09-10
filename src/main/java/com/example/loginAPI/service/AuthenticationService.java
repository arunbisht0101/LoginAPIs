package com.example.loginAPI.service;

import com.example.loginAPI.dto.LoginRequest;
import com.example.loginAPI.dto.LoginResponse;
import com.example.loginAPI.dto.RegisterRequest;
import com.example.loginAPI.entity.User;
import com.example.loginAPI.repository.UserRepository;
import com.example.loginAPI.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public LoginResponse login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            var userDetails = (UserDetails) authentication.getPrincipal();
            log.info("userDetails::"+userDetails);
            var jwtToken = jwtService.generateToken(userDetails);

            log.info("User {} logged in successfully", request.getEmail());

            return LoginResponse.builder()
                    .token(jwtToken)
                    .expiresIn(jwtService.getExpirationTime() / 1000)
                    .message("Login successful")
                    .build();

        } catch (DisabledException e) {
            log.warn("Login failed - user account is disabled: {}", request.getEmail());
            throw new RuntimeException("User account is disabled. Please contact administrator.");
        } catch (BadCredentialsException e) {
            log.warn("Invalid credentials for email: {}", request.getEmail());
            throw new RuntimeException("Invalid email or password");
        } catch (AuthenticationException e) {
            log.warn("Authentication failed for email: {}", request.getEmail(), e);
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error during login for email: {}", request.getEmail(), e);
            throw new RuntimeException("Internal server error during login");
        }
    }

    public LoginResponse register(RegisterRequest request) {
        try {
            if (!request.getPassword().equals(request.getConfirmPassword())) {
                throw new RuntimeException("Passwords do not match");
            }

            if (userRepository.existsByEmail(request.getEmail())) {
                throw new RuntimeException("Email already exists");
            }

            var user = User.builder()
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .enabled(true)  // Explicitly set enabled to true
                    .build();

            userRepository.save(user);

            // Create UserDetails for token generation
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                    .withUsername(request.getEmail())
                    .password(user.getPassword())
                    .authorities("USER")
                    .accountExpired(false)
                    .accountLocked(false)
                    .credentialsExpired(false)
                    .disabled(false)  // Ensure user is not disabled
                    .build();

            var jwtToken = jwtService.generateToken(userDetails);

            log.info("User {} registered successfully", request.getEmail());

            return LoginResponse.builder()
                    .token(jwtToken)
                    .expiresIn(jwtService.getExpirationTime() / 1000)
                    .message("Registration successful")
                    .build();
        } catch (Exception e) {
            log.error("Registration failed for email: {}", request.getEmail(), e);
            throw new RuntimeException("Registration failed: " + e.getMessage());
        }
    }
}