package com.keplara.auth_service.model.jwt;
import lombok.Data;

@Data
public class CreateAccountJwt {

    private String username;
    private String emailAddress;
    private String password;

    public CreateAccountJwt(String username, String emailAddress, String password){
        this.username = username;
        this.emailAddress = emailAddress;
        this.password = password;
    }

    public CreateAccountJwt() {}

}
