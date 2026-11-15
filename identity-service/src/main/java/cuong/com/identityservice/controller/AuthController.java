package cuong.com.identityservice.controller;

import cuong.com.identityservice.dto.AuthResponse;
import cuong.com.identityservice.entity.RefreshToken;
import cuong.com.identityservice.entity.User;
import cuong.com.identityservice.security.JwtUtils;
import cuong.com.identityservice.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping({"/api/auth", "/api/v1/auth"})
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public record LoginRequest(String username, String password) {}

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        // 1. Xác thực username/password
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        // Lấy đối tượng User đã xác thực
        User user = (User) authentication.getPrincipal();

        // 2. Tạo Access Token (JWT)
        String accessToken = jwtUtils.generateAccessToken(user);

        // 3. Tạo Refresh Token (UUID lưu trong DB)
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        // 4. Trả về DTO chứa cả hai
        return ResponseEntity.ok(AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .build());
    }
}