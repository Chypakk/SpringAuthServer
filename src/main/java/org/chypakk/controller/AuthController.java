package org.chypakk.controller;

import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.chypakk.model.RefreshToken;
import org.chypakk.repository.RefreshTokenRepository;
import org.chypakk.util.JwtUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@Controller
@RequestMapping("api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepo;
    private final JwtUtils jwtUtils;


    public AuthController(AuthenticationManager authenticationManager, RefreshTokenRepository refreshTokenRepository,
                          JwtUtils jwtUtils) {

        this.authenticationManager = authenticationManager;
        this.refreshTokenRepo = refreshTokenRepository;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam("username") String username,
                                   @RequestParam("password") String password,
                                   HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            username,
                            password
                    )
            );

            String accessToken = jwtUtils.generateAccessToken(username);
            String refreshToken = jwtUtils.generateRefreshToken(username);

            refreshTokenRepo.save(new RefreshToken(
                    refreshToken,
                    username,
                    Instant.now().plusMillis(jwtUtils.getRefreshTokenExpirationMs())
            ));

            Cookie accessCookie = createCookie("access_token", accessToken, jwtUtils.getAccessTokenExpirationMs());
            Cookie refreshCookie = createCookie("refresh_token", refreshToken, jwtUtils.getRefreshTokenExpirationMs());
            response.addCookie(accessCookie);
            response.addCookie(refreshCookie);

            return ResponseEntity.ok().body("Welcome " + username);
        } catch (JOSEException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@CookieValue(name = "refresh_token") String refreshToken,
                                          HttpServletResponse response){
        if (!jwtUtils.validateToken(refreshToken) || !jwtUtils.isRefreshToken(refreshToken)){
            return ResponseEntity.badRequest().body("Invalid refresh token");
        }

        RefreshToken storedToken = refreshTokenRepo.findByToken(refreshToken).orElse(null);
        if (storedToken == null) return ResponseEntity.badRequest().body("Invalid refresh token");

        if(storedToken.getExpiryData().isBefore(Instant.now())) return ResponseEntity.badRequest().body("ничего не понимаю");

        refreshTokenRepo.delete(storedToken);
        String username = jwtUtils.getUsernameFromToken(refreshToken);
        try {
            String newAccessToken = jwtUtils.generateAccessToken(username);
            String newRefreshToken = jwtUtils.generateRefreshToken(username);

            refreshTokenRepo.save(new RefreshToken(
                    refreshToken,
                    username,
                    Instant.now().plusMillis(jwtUtils.getRefreshTokenExpirationMs())
            ));

            Cookie accessCookie = createCookie("access_token", newAccessToken, jwtUtils.getAccessTokenExpirationMs());
            Cookie refreshCookie = createCookie("refresh_token", newRefreshToken, jwtUtils.getRefreshTokenExpirationMs());
            response.addCookie(accessCookie);
            response.addCookie(refreshCookie);
            return ResponseEntity.ok().build();

        } catch (JOSEException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @CookieValue(name = "refresh_token") String refreshToken,
            HttpServletResponse response
    ){
        refreshTokenRepo.deleteByToken(refreshToken);
        clearCookiesLegacy(response);

        return ResponseEntity.ok().build();
    }

    private Cookie createCookie(String type, String token, long duration){
        Cookie cookie = new Cookie(type, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge((int)duration / 1000);
        cookie.setPath("/");

        return cookie;

    }

    public static void clearCookiesLegacy(HttpServletResponse response) {
        // Для access_token
        Cookie accessCookie = new Cookie("access_token", null);
        accessCookie.setMaxAge(0);
        accessCookie.setPath("/");
        response.addCookie(accessCookie);

        // Для refresh_token
        Cookie refreshCookie = new Cookie("refresh_token", null);
        refreshCookie.setMaxAge(0);
        refreshCookie.setPath("/api/auth/refresh");
        response.addCookie(refreshCookie);
    }
}
