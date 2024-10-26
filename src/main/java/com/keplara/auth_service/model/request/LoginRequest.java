package com.keplara.auth_service.model.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "username is required.")
    private String username;
    
    @NotBlank(message = "password is required.")
    private String password;

}