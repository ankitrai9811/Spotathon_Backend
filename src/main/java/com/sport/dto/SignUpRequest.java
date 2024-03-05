package com.sport.dto;

import com.sport.entities.UserRole;
import lombok.Data;

@Data
public class SignUpRequest {

    private long sapid;
    private String name;
    private String email;
    private String password;
}
