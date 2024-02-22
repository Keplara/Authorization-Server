package com.keplara.auth_service.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.Message.RecipientType;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.google.api.client.googleapis.json.GoogleJsonError;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.Draft;
import com.google.api.services.gmail.model.Label;
import com.google.api.services.gmail.model.ListLabelsResponse;
import com.google.api.services.gmail.model.Message;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.mongodb.lang.Nullable;

@Service
public class GoogleService {

    private static final String APPLICATION_NAME = "keplara";

    @Value("${server.port}")
    @Nullable
    private Integer port;

    private Gmail service;

    public GoogleService() throws GeneralSecurityException, IOException {}

    public GoogleCredentials getCredentials() throws IOException{
        // GoogleCredentials.
        return GoogleCredentials.getApplicationDefault()
        .createScoped(GmailScopes.GMAIL_SEND)
        .createDelegated("no-reply@keplara.com");
    }

    public void sendEmail(String bodyText, String messageSubject, String toEmailAddress) throws IOException, MessagingException, GeneralSecurityException{
        
        final HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(getCredentials());
        this.service = new Gmail.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance(), requestInitializer).build();
    

            // Encode as MIME message
            Properties props = new Properties();
            Session session = Session.getDefaultInstance(props, null);
            MimeMessage email = new MimeMessage(session);
            email.setFrom(new InternetAddress("no-reply@keplara.com"));
            email.addRecipient(javax.mail.Message.RecipientType.TO,new InternetAddress(toEmailAddress));
            email.setSubject(messageSubject);

            // MimeBodyPart mimeBodyPart = new MimeBodyPart();
            // mimeBodyPart.setContent(bodyText, "text/plain");
            
            // Multipart multipart = new MimeMultipart();
            // multipart.addBodyPart(mimeBodyPart);
            // mimeBodyPart = new MimeBodyPart();
            
            // DataSource source = new FileDataSource(file);
            // mimeBodyPart.setDataHandler(new DataHandler(source));
            // mimeBodyPart.setFileName(file.getName());
            // multipart.addBodyPart(mimeBodyPart);
            // upload images
            // email.setContent(multipart);

            // Encode and wrap the MIME message into a gmail message
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            email.setText(bodyText);
            email.writeTo(buffer);
            
            byte[] rawMessageBytes = buffer.toByteArray();

            Message message = new Message();
            message.encodeRaw(rawMessageBytes);

            try {
                service.users().messages().send("me", message);
            } catch (GoogleJsonResponseException e) {
            // TODO(developer) - handle error appropriately
            GoogleJsonError error = e.getDetails();
            if (error.getCode() == 403) {
                System.err.println("Unable to create draft: " + e.getDetails());
            } else {
                throw e;
            }
        }
      }

}
