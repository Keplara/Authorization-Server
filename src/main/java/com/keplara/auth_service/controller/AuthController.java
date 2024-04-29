package com.keplara.auth_service.controller;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.keplara.auth_service.configuration.ResponseLog;
import com.keplara.auth_service.configuration.exceptions.AuthApiException;
import com.keplara.auth_service.model.jwt.CreateAccountJwt;
import com.keplara.auth_service.model.mongo.User;

import com.keplara.auth_service.model.request.CreateAccountRequest;
import com.keplara.auth_service.service.AuthService;
import com.keplara.auth_service.service.GoogleService;
import com.keplara.auth_service.service.TokenService;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;

import javax.mail.MessagingException;

import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@Validated
public class AuthController {
	private AuthService authService;
	private GoogleService googleService;
	private TokenService tokenService;

	public AuthController(AuthService authService, GoogleService googleService, TokenService tokenService){
		this.authService = authService;
		this.tokenService = tokenService;
		this.googleService = googleService;
	}

	@ExceptionHandler(value = {  AuthApiException.class })
    protected ResponseEntity<String> handleExceptions(AuthApiException ex) {
        return new ResponseEntity<String>(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

	@PostMapping("/create-account")
	public String createAccount(@RequestBody(required = false) CreateAccountRequest accountRequest) throws AuthApiException, IOException, MessagingException, GeneralSecurityException {
		User existingUserByEmail = authService.getUser(accountRequest.getEmailAddress());

		if (existingUserByEmail != null){
			throw new AuthApiException(String.format("User with email '%s' already exist.", existingUserByEmail.getEmailAddress()));
		} else {
			String accountJwtToken = tokenService.createAccountToken(accountRequest.getEmailAddress(), accountRequest.getPassword(), accountRequest.getUsername());	
			googleService.sendEmail("Click the link below to create your account. Once you click the link you will be redirected to keplara.com as a signed in user. Thank you for signing up with us today! \n \n https://keplara.com/verify-new-account?token="+accountJwtToken, "Create Account", accountRequest.getEmailAddress());
			return accountJwtToken;
		}
	}

	@GetMapping("/verify-new-account")
	public ResponseEntity<Object> verifyAccount(@RequestParam(name = "token") String token) throws AuthApiException, URISyntaxException {
		CreateAccountJwt account = tokenService.parseAccountToken(token);
		User existingUser = authService.getUser(account.getUsername());
		if (existingUser != null){
			throw new AuthApiException(String.format("User '%s' has already been created.", existingUser.getUserId()));
		}
		authService.CreateUser(account.getUsername(), account.getEmailAddress(), account.getPassword());
		
		ResponseLog response = new ResponseLog(String.format("Account has been created for %s.", account.getEmailAddress()), HttpStatus.OK);
		return response.getResponse();
	}

	@PostMapping("/login")
	public void login(@RequestBody CreateAccountRequest accountRequest, @RequestParam(name="phoneVerification") Boolean phoneVerification ) {
	}

	
	// make reuseable magic link
	@PostMapping("/forgot-password")
	public void forgotPassword(@RequestParam(name = "emailAddress") String emailAddress) {
	}

	// update.user.password
	@PostMapping("/update-user-password")
	public void updateUserPassword(Authentication authentication) {
	}

	// user with scope user.twoFactor
	@PostMapping("/2fa-verification")
	public void twofactorVerification(Authentication authentication) {
	}
		
	// user with scope user.totp
	@PostMapping("/totp-verification")
	public void totpVerification(Authentication authentication) {

	}

	// user role is admin
	// user scops admin.create.account
	@PostMapping("/create-admin-account")
	public void createAdminAccount(@RequestBody CreateAccountRequest accountRequest, @RequestParam(name="phoneVerification") Boolean phoneVerification ) {
	}


	// no scopes requred or authorities, just the token
	@PutMapping("/logout/{userId}")
	public void logout(Authentication authentication) {
	}

}
