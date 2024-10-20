package com.keplara.auth_service.controller;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.keplara.auth_service.service.SimpleEmailService;
import com.keplara.auth_service.configuration.ResponseLog;
import com.keplara.auth_service.configuration.exceptions.AuthApiException;
import com.keplara.auth_service.model.jwt.AccountToken;
import com.keplara.auth_service.model.mongo.User;
import com.keplara.auth_service.model.request.CreateAccountRequest;
import com.keplara.auth_service.model.request.LoginRequest;
import com.keplara.auth_service.service.AuthService;
import com.keplara.auth_service.service.GoogleService;
import com.keplara.auth_service.service.TokenService;


import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import javax.mail.MessagingException;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@Validated
public class AuthController {
	private final AuthService authService;
	private final GoogleService googleService;
	private final TokenService tokenService;
	private final SimpleEmailService simpleEmailService;

	@Autowired
	private RedisTemplate<String, String> redisTemplate;

	@Autowired
    private PasswordEncoder passwordEncoder;


	public AuthController(SimpleEmailService simpleEmailService, AuthService authService, GoogleService googleService, TokenService tokenService){
		this.authService = authService;
		this.tokenService = tokenService;
		this.googleService = googleService;
		this.simpleEmailService = simpleEmailService;

	}

    @PostMapping("send-test-email")
    public String sendTestEmail(){
        this.simpleEmailService.sendEmail("grantmitchell@keplara.com", "First Email Subject", null);
        return "Email sent successfully!";
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
		AccountToken account = tokenService.parseAccountToken(token);
		User existingUser = authService.getUser(account.getUsername());
		if (existingUser != null){
			throw new AuthApiException(String.format("User '%s' has already been created.", existingUser.getUserId()));
		}
		authService.createUser(account.getUsername(), account.getEmailAddress(), account.getPassword());
		
		ResponseLog response = new ResponseLog(String.format("Account has been created for %s.", account.getEmailAddress()), HttpStatus.OK);
		return response.getResponse();
	}

	// authorization client calls
    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest) throws AuthenticationException, AuthApiException, MalformedURLException {
		User user = authService.getUser(loginRequest.getUsername());
		if (user == null){
			throw new AuthApiException("User does not exist, please verify the credentials you are entering are correct.");
		}

		String encryptedPasswordFromDatabase = user.getPassword(); // Assuming getPassword() returns the encrypted password
    
		boolean passwordMatch = passwordEncoder.matches(loginRequest.getPassword(), encryptedPasswordFromDatabase);
		
		if (!passwordMatch) {
			throw new AuthApiException("Invalid username or password."); // or return an error message indicating invalid credentials
		}

		String authorizationCode = "iofnwoinfewifn"; // generate this randomly
		// Define the expiration time for the authorization code
		Duration expiration = Duration.ofMinutes(3); // Example: Expires after 30 minutes

		// Set the authorization code in Redis with the specified expiration time
		String authorizationCodeKey = "authorizationCode:" + authorizationCode;
		String userIdValue = user.getUserId();
		redisTemplate.opsForValue().set(authorizationCodeKey, userIdValue, expiration);
		// send back redirect uri
		return new LoginResponse(authorizationCode);
	}

	@PutMapping("/logout/{userId}")
	public void logout(Authentication authentication) {
		// remove reddis token attached to user.
	}

}
