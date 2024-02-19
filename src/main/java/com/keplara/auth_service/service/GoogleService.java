package com.keplara.auth_service.service;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Message.RecipientType;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
// import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
// import com.google.api.client.http.javanet.NetHttpTransport;
// it doesn't matter at the moment to push to git because we are doing anaylisis while coding. 
// Until we have an official project for the auth service and e
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;

import com.google.api.client.googleapis.json.GoogleJsonError;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.Message;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.mongodb.lang.Nullable;

@Service
public class GoogleService {
    private static final String APPLICATION_NAME = "Keplara";
    private static final String TOKEN_PATH = "/token.json";
    private static final String[] SCOPES = {"https://www.googleapis.com/auth/gmail.send","https://www.googleapis.com/auth/userinfo.email"};
    private static final String CREDENTIALS_FILE_PATH = "/credentials.json";
    private static final String SERVICE_ACCOUNT_KEY_FILE = "/key.json";
    private static final String REDIRECT_URI = "/code";


    @Value("${server.port}")
    @Nullable
    private Integer port;

    private Gmail service;

    public GoogleService() throws GeneralSecurityException, IOException {
        // Build a new authorized API client service.
        this.port = this.port != null ? this.port : 8080;

        InputStream in = GoogleService.class.getResourceAsStream(SERVICE_ACCOUNT_KEY_FILE);
        if (in == null) {
            throw new FileNotFoundException("Resource not found: " + SERVICE_ACCOUNT_KEY_FILE);
        }
        // Load credentials from the service account key file
        GoogleCredentials credentials = ServiceAccountCredentials.fromStream(in).createScoped(GmailScopes.GMAIL_SEND).createDelegated("no-reply@keplara.com");
		final HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);

        this.service = new Gmail.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance(),
                        requestInitializer).setApplicationName(APPLICATION_NAME).build();
    }

    // private void setCredentialsFromFile(JsonFactory jsonFactory) throws IOException {
    //     googleClientSecrets = GoogleClientSecrets.load(
    //         jsonFactory,
    //         new InputStreamReader(
    //             GoogleService.class.getResourceAsStream("/client_secrets.json"), "UTF-8"
    //         )
    //     ); 
    // }

    // private void requestAccessToken() throws IOException {

    //     // if (googleClientSecrets == null){
    //     //     setCredentialsFromFile(JSON_FACTORY);
    //     // }
    //     // googleClientSecrets.getDetails().getClientId()
    //     try {
    //         GoogleTokenResponse response = new GoogleAuthorizationCodeTokenRequest(
    //             new NetHttpTransport(), 
    //             new GsonFactory(),
    //             googleClientSecrets.getDetails().getClientId(),
    //             googleClientSecrets.getDetails().getClientSecret(),
    //             "4/P7q7W91a-oMsCeLvIaQm6bTrgtp7",
    //             googleClientSecrets.getDetails().getRedirectUris().get(0)
    //         ).execute();
    //         System.out.println("Access token: " + response.getAccessToken());
    //     } catch (TokenResponseException e) {
    //         if (e.getDetails() != null) {
    //         System.err.println("Error: " + e.getDetails().getError());
    //         if (e.getDetails().getErrorDescription() != null) {
    //             System.err.println(e.getDetails().getErrorDescription());
    //         }
    //         if (e.getDetails().getErrorUri() != null) {
    //             System.err.println(e.getDetails().getErrorUri());
    //         }
    //         } else {
    //         System.err.println(e.getMessage());
    //         }
    //     }
    // }
 
        // change this to use env vars that use the json cred files

    public void sendEmail(String bodyText, String messageSubject, String toEmailAddress) throws IOException, MessagingException, GeneralSecurityException{
    //     GoogleCredentials credentials = GoogleCredentials.getApplicationDefault()
    //         .createScoped(GmailScopes.GMAIL_SEND);
    //     HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);

        // Encode as MIME message
        Properties props = new Properties();
        Session session = Session.getDefaultInstance(props, null);
        MimeMessage email = new MimeMessage(session);
        email.setFrom(new InternetAddress("no-reply@keplara.com"));
        email.addRecipient(RecipientType.TO,
            new InternetAddress(toEmailAddress));
        email.setSubject(messageSubject);
        email.setText(bodyText);

        // Encode and wrap the MIME message into a gmail message
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        email.writeTo(buffer);
        byte[] rawMessageBytes = buffer.toByteArray();
        String encodedEmail = Base64.getEncoder().encodeToString(rawMessageBytes);
        Message message = new Message();
        message.setRaw(encodedEmail);

        try {
        // Create send message
        Message sentMessage = service.users().messages().send("me", message).execute();
            System.out.println("Message id: " + sentMessage .getId());
            System.out.println(sentMessage .toPrettyString());
        } catch (GoogleJsonResponseException e) {
            // TODO(developer) - handle error appropriately
            GoogleJsonError error = e.getDetails();
            if (error.getCode() == 403) {
                System.err.println("Unable to send message: " + e.getDetails());
            } else {
                throw e;
            }
        }    
      }

}
