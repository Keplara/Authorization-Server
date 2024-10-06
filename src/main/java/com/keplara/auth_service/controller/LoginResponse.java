package com.keplara.auth_service.controller;

import lombok.Data;

@Data
public class LoginResponse {

    private String code;

    public LoginResponse(String authorizationCode) {
        this.code = authorizationCode;
    }

}
