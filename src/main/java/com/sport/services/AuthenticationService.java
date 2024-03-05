package com.sport.services;

import com.sport.dto.JwtAuthenticationResponse;
import com.sport.dto.RefreshTokenRequest;
import com.sport.dto.SignUpRequest;
import com.sport.dto.SigninRequest;
import com.sport.entities.User;

public interface AuthenticationService {

    User signup(SignUpRequest signUpRequest);
    JwtAuthenticationResponse sigin(SigninRequest signinRequest);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
