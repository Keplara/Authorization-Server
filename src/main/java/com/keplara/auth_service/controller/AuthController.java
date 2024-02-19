package com.keplara.auth_service.controller;


// github grant15558

// import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;

import com.keplara.auth_service.configuration.exceptions.AuthApiException;
import com.keplara.auth_service.model.jwt.CreateAccountJwt;
import com.keplara.auth_service.model.mongo.User;

// import com.keplara.auth_service.model.mongo.Session;

import com.keplara.auth_service.model.request.CreateAccountRequest;
import com.keplara.auth_service.repository.UserRepository;
import com.keplara.auth_service.service.AuthService;
import com.keplara.auth_service.service.GoogleService;
import com.keplara.auth_service.service.TokenService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;

import javax.mail.MessagingException;
import javax.mail.internet.AddressException;

import org.apache.catalina.authenticator.SpnegoAuthenticator.AuthenticateAction;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties.Authentication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestHeader;
// import org.springframework.web.bind.annotation.PutMapping;
// import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.PathVariable;

@RestController
@Validated
public class AuthController {

	private AuthService authService;
	private GoogleService googleService;
	private TokenService tokenService;

	// auth service 

	public AuthController(AuthService authService, GoogleService googleService, TokenService tokenService){
		this.authService = authService;
		this.tokenService = tokenService;
		this.googleService = googleService;
	}

	@ExceptionHandler(value = {  AuthApiException.class })
    protected ResponseEntity<String> handleExceptions(AuthApiException ex) {
		System.out.println(ex.getMessage());
        return new ResponseEntity<String>(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

	// TODO
	@PostMapping("/create-account")
	public String createAccount(@RequestBody(required = false) CreateAccountRequest accountRequest) throws AuthApiException, IOException, MessagingException, GeneralSecurityException {
		User existingUser = authService.getUser(accountRequest.getUsername());

		if (existingUser != null){
			throw new AuthApiException(String.format("User '%s' already exist.", existingUser.getUserId()));
		} else {
			String accountJwtToken = tokenService.createAccountToken(accountRequest.getEmailAddress(), accountRequest.getPassword(), accountRequest.getUsername());	
			// the redirect will go to the client proxy hosting keplara.com domain or if it is a mobile device it should ask to open the app. The client will redirect from that point once the respose has been recieved
			googleService.sendEmail("Click the link below to create your account. Once you click the link you will be redirected to keplara.com as a signed in user. Thank you for signing up with us today! \n \n https://keplara.com/verify-account?token="+accountJwtToken, "Create Account", accountRequest.getEmailAddress());
			return accountJwtToken;
		}
	}

	@GetMapping("/verify-account")
	public ResponseEntity<Object> verifyAccount(@RequestParam(name = "token") String token) throws AuthApiException, URISyntaxException {
		CreateAccountJwt account = tokenService.parseAccountToken(token);
		// create account

		// authService.createAccount(account.getEmailAddress(), account.getUsername(), account.getPassword());

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setLocation(new URI("https://keplara.com"));
		return new ResponseEntity<>(account.getEmailAddress(), httpHeaders, HttpStatus.SEE_OTHER);
	}

	@PostMapping("/login")
	public void login(@RequestBody CreateAccountRequest accountRequest, @RequestParam(name="phoneVerification") Boolean phoneVerification ) {
		// find user
		// check password 
		// if 2fa do 2fa
		
		// if 2fa mobile return object for 2fa verificaiton or when client recieves token then go to 2fa page with jwtUserDetails
		// if error then client will error to user
		// steps for 2fa
		// 1 create userDetailsObject jwt for creating a session token {userId} time 30 minutes
		// 2 create ibe tune code and attach it to the user in the database
		// 3 send code to phone number
		// 4 return token to client
		// when 2fa-verification route is called it takes the JWT and creates the user session and access token. These get send back to the client. 

		// TODO 2fa authenticator
		// create access token and session
	}

	
	// make reuseable magic link
	@PostMapping("/forgot-password")
	public void forgotPassword(@RequestParam(name = "emailAddress") String emailAddress) {
		// if route is hit again reassign accessToken
		// create magic link with access token assigned to user accessToken 
		// when user logs in the new access token will replace the expired access token.
		// once update-user-password route is hit, access token is removed

		// if phone 2factor is true then client will go to the 2factor page and ask for phone code. comparison called the /2factor route and it checks user 
		// generate totp code
		// store code in 
	}

	// update.user.password
	@PostMapping("/update-user-password")
	public void updateUserPassword(Authentication authentication) {
		// extract resetPasswordToken
		// get 
		//authentication.getToken()
		// find user by email
		// with user details send magic link to email.
		// in the magic link will update user password
	}

	// user with scope user.twoFactor
	@PostMapping("/2fa-verification")
	public void twofactorVerification(Authentication authentication) {
		// set up later		
		// twillo
		// recieves user jwt object on Authetnication and checks if the token is expired.
		// checks 2fa generated code if it matches in the database then create user session and accessToken
		// return session and access token for client
	}
		
	// user with scope user.totp
	@PostMapping("/totp-verification")
	public void totpVerification(Authentication authentication) {
		// do not set this up it is for google authenticator
		// only for admins		
	}

	// user role is admin
	// user scops admin.create.account
	@PostMapping("/create-admin-account")
	public void createAdminAccount(@RequestBody CreateAccountRequest accountRequest, @RequestParam(name="phoneVerification") Boolean phoneVerification ) {
		// set the user and scopes
		// Only an admin account with the scope create.admin.account can create admin accounts
		// All other admins and other users cannot create access this route. 
	}


	// no scopes requred or authorities, just the token
	@PutMapping("/logout/{userId}")
	public void logout(Authentication authentication) {
		//TODO: process PUT request
		// get token authentication.getToken 
		// with user detils log out
		// remove sessions

	}

	// depending on the route scopes are created based off the user details
	// say a route subscribe which means user subscribed to our service providing the a payment method to a third party payment platform
	// a scope will be added user.get.labresults
	// only subscribed users can get the labresults

}
