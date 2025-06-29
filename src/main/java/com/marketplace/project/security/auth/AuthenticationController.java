package com.marketplace.project.security.auth;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.marketplace.project.Dtos.request.AuthenticationRequest;
import com.marketplace.project.Dtos.request.RegisterRequest;
import com.marketplace.project.Dtos.response.AuthenticationResponse;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    /**
     * Inscription d'un nouvel utilisateur
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisterRequest request) {
        System.out.println("Endpoint /register appelé!");
        System.out.println("Données reçues : " + request);
        return ResponseEntity.ok(authenticationService.register(request));
    }

    /**
     * Connexion d'un utilisateur
     */
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@Valid @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Token invalide");
        }
        String token = authHeader.substring(7);
        authenticationService.logout(token);
        return ResponseEntity.ok("Déconnexion réussie");
    }

    /**
     * Rafraîchir un token JWT
     */
    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authenticationService.refreshToken(request, response);
    }
}
