package com.keplara.auth_service.controller;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.ObjectIdGenerators.UUIDGenerator;
import com.keplara.auth_service.configuration.ResponseLog;
import com.keplara.auth_service.configuration.exceptions.AuthApiException;
import com.keplara.auth_service.model.IdToken;
import com.keplara.auth_service.model.OidcRequest;
import com.keplara.auth_service.model.jwt.AccountToken;
import com.keplara.auth_service.model.mongo.Session;
import com.keplara.auth_service.model.mongo.User;
import com.keplara.auth_service.service.RegisterClientResponse;
import com.keplara.auth_service.model.request.CreateAccountRequest;
import com.keplara.auth_service.model.request.LoginRequest;
import com.keplara.auth_service.service.AuthService;
import com.keplara.auth_service.service.GoogleService;
import com.keplara.auth_service.service.TokenService;
import java.util.UUID;

import io.jsonwebtoken.security.Jwks.OP;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import javax.mail.MessagingException;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.tomcat.util.http.parser.Authorization;
import org.checkerframework.common.returnsreceiver.qual.This;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties.Jedis;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@RestController
@Validated
public class AuthController {
	private AuthService authService;
	private GoogleService googleService;
	private TokenService tokenService;

	@Autowired
	private RedisTemplate<String, String> redisTemplate;

	@Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

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
		AccountToken account = tokenService.parseAccountToken(token);
		User existingUser = authService.getUser(account.getUsername());
		if (existingUser != null){
			throw new AuthApiException(String.format("User '%s' has already been created.", existingUser.getUserId()));
		}
		authService.createUser(account.getUsername(), account.getEmailAddress(), account.getPassword());
		
		ResponseLog response = new ResponseLog(String.format("Account has been created for %s.", account.getEmailAddress()), HttpStatus.OK);
		return response.getResponse();
	}

	// authorization client
	@GetMapping("/register-client")
	public RegisterClientResponse registerClient(){
        UUID clientId = UUID.randomUUID();
		String clientSecret = DigestUtils.sha256Hex(clientId.toString());
		return authService.registerClient(clientId.toString(), clientSecret);
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

	// main app calls
	@PostMapping("/token")
	public TokenResponse getToken(@RequestParam("code") String authorizationCode) {
		String authorizationCodeKey = "authorizationCode:" + authorizationCode;
		String userId = redisTemplate.opsForValue().get(authorizationCodeKey);
		if (userId == null){
			throw new AuthApiException("authorizationCode has expired or is invalid please login again.");
		}
		Session userSession = new Session(userId);
		authService.createSession(userSession);
		IdToken token = authService.createIdToken(userSession);
		return new TokenResponse(tokenService.createIdToken(token), new accessToken(user.roles, userId, user.grants, hours));

	}
	


	@GetMapping("/authorize")
	public void authroize(@RequestHeader("Authorization") String token) {
		// check validity of token
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
