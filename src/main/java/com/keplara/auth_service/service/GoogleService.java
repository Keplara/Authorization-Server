package com.keplara.auth_service.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.Session;

import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.google.api.client.googleapis.json.GoogleJsonError;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;

import com.google.api.services.gmail.model.Message;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.ServiceAccountCredentials;

@Service
public class GoogleService {

    private static final String APPLICATION_NAME = "Keplara";
    
    @Value("${service_account_key_file}")
    private String SERVICE_ACCOUNT_KEY_FILE;

    public GoogleService() {}

    private ServiceAccountCredentials getCredentials() throws IOException {
        InputStream in = GoogleService.class.getResourceAsStream(SERVICE_ACCOUNT_KEY_FILE);
        ServiceAccountCredentials credentials = (ServiceAccountCredentials) ServiceAccountCredentials.fromStream(in)
        .createScoped(GmailScopes.GMAIL_SEND)
        .createDelegated("no-reply@keplara.com");
        return credentials;
    }

    public void sendEmail(String bodyText, String messageSubject, String toEmailAddress) throws IOException, MessagingException, GeneralSecurityException {
        final HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(getCredentials());
        Gmail service = new Gmail.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance(),
        requestInitializer).setApplicationName(APPLICATION_NAME).build();

        // Encode as MIME message
        Properties props = new Properties();
        Session session = Session.getDefaultInstance(props, null);
        MimeMessage email = new MimeMessage(session);
        email.setFrom(new InternetAddress("no-reply@keplara.com"));
        email.addRecipient(javax.mail.Message.RecipientType.TO, new InternetAddress(toEmailAddress));
        email.setSubject(messageSubject);
        email.setText(bodyText);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        email.writeTo(buffer);
        
        byte[] rawMessageBytes = buffer.toByteArray();

        Message message = new Message();
        message.encodeRaw(rawMessageBytes);

        try {
            service.users().messages().send("me", message).execute();
        } catch (GoogleJsonResponseException e) {
        GoogleJsonError error = e.getDetails();
        if (error.getCode() == 403) {
            System.err.println("Unable to create email: " + e.getDetails());
        } else {
            throw e;
        }
    }
    }

}
