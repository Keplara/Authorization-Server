package com.keplara.auth_service.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwsHeader.Builder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;

import com.keplara.auth_service.cache.RedisRegisteredClientRepository;
import com.keplara.auth_service.repository.RegisteredClientRepository;
import com.keplara.auth_service.service.OAuth2AuthorizationService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.jsonwebtoken.JwsHeader;

import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.UUID;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private final OAuth2AuthorizationService oauth2AuthorizationService;

	@Bean 
	public RedisRegisteredClientRepository registeredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("oidc-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://127.0.0.1:8082/login/oauth2/code/oidc-client")
				.postLogoutRedirectUri("http://127.0.0.1:4200/")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();

		return new RedisRegisteredClientRepository(oidcClient);
	}

	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator() {
		JwtEncoder jwtEncoder = ...;
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(jwtCustomizer());
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(
				jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return context -> {
			Builder headers = context.getJwsHeader();
			JwtClaimsSet.Builder claims = context.getClaims();
			if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
				// Customize headers/claims for access_token
				// grants and roles
				// expdatetime
				//iss time
			} else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
				// Customize headers/claims for id_token
				// create id token
			}
		};
	}


	@Bean 
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					// proxy to port 8082 then later proxy to oauth.keplara.com client
					new LoginUrlAuthenticationEntryPoint("http://127.0.0.1:8082/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer((resourceServer) -> resourceServer
				.jwt(Customizer.withDefaults()));

		return http.build();
	}

	@Bean 
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	@SuppressWarnings("rawtypes")
	private static KeyPair generateRsaKey() { 
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean 
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
		configuration.setAllowedOrigins(Arrays.asList("http://localhost:8082"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
		new OAuth2AuthorizationServerConfigurer();

		authorizationServerConfigurer
			.registeredClientRepository(registeredClientRepository()) 
			// later create own configure class off of OAuth2AuthorizationServiceConfigurer
			.authorizationService((org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService) oauth2AuthorizationService) 
			.authorizationServerSettings(authorizationServerSettings) 
			.tokenGenerator(tokenGenerator) 
			.clientAuthentication(clientAuthentication -> { })  
			.authorizationEndpoint(authorizationEndpoint -> { })    
			.deviceAuthorizationEndpoint(deviceAuthorizationEndpoint -> { })    
			.deviceVerificationEndpoint(deviceVerificationEndpoint -> { })  
			.tokenEndpoint(tokenEndpoint -> { })    
			.tokenIntrospectionEndpoint(tokenIntrospectionEndpoint -> { })  
			.tokenRevocationEndpoint(tokenRevocationEndpoint -> { })    
			.authorizationServerMetadataEndpoint(authorizationServerMetadataEndpoint -> { })    
			.oidc(oidc -> oidc
				.providerConfigurationEndpoint(providerConfigurationEndpoint -> { })    
				.logoutEndpoint(logoutEndpoint -> { })  
				.userInfoEndpoint(userInfoEndpoint -> { })  
				.clientRegistrationEndpoint(clientRegistrationEndpoint -> { })  
			);

        http
        	.cors(cors-> cors.configurationSource(corsConfigurationSource()))
			.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults())) 
            .authorizeHttpRequests((authorizeHttpRequests) ->
                authorizeHttpRequests
				.authorizationServerConfigurer(authorizationServerConfigurer)
				.requestMatchers(HttpMethod.POST, "/login").permitAll()
                    .requestMatchers(HttpMethod.POST, "/create-account").permitAll()
                    .requestMatchers(HttpMethod.GET, "/verify-new-account").permitAll()
                    .requestMatchers(HttpMethod.POST, "/reset-password").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.POST, "/create-product").hasAuthority("create.product")
                    .requestMatchers(HttpMethod.PUT, "/update-product").hasAuthority("update.product")
                    .anyRequest().authenticated()
            );
	

        return http.build();
    }

}