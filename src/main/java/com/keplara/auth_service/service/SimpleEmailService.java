package com.keplara.auth_service.service;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.Content;
import software.amazon.awssdk.services.ses.model.Destination;
import software.amazon.awssdk.services.ses.model.Message;
import software.amazon.awssdk.services.ses.model.Body;
import software.amazon.awssdk.services.ses.model.SendEmailRequest;
import software.amazon.awssdk.services.ses.model.SesException;
import software.amazon.awssdk.services.ses.model.Template;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;

@Service
public class SimpleEmailService {

    @Value("${aws.key_id}")
    private String keyId;
    @Value("${aws.key}")
    private String key;

    public SimpleEmailService(){}

    public void sendEmail(Template template) {
        
    }

    public void sendEmail(String emailAddress, String subject, String body) {
        // final String usage = """

        //         Usage:
        //             <sender> <recipient> <subject>\s

        //         Where:
        //             sender - An email address that represents the sender.\s
        //             recipient -  An email address that represents the recipient.\s
        //             subject - The  subject line.\s
        //         """;


        String sender = "no-reply@keplara.com";
        String recipient = emailAddress;
        subject = subject.isEmpty() ? "Default Subject" : subject;
        Region region = Region.US_EAST_1;
        AwsCredentials  basicCreds = (AwsCredentials) AwsBasicCredentials.builder().accessKeyId(keyId).secretAccessKey(key).build();
        AwsCredentialsProvider awsCredentialsProvider = StaticCredentialsProvider.create(basicCreds);

        SesClient client = SesClient.builder()
                .region(region)
                .credentialsProvider(awsCredentialsProvider)
                .build();

        // The HTML body of the email.
        String bodyHTML = "<html>" + "<head></head>" + "<body>" + "<h1>Hello!</h1>"
                + "<p> See the list of customers.</p>" + "</body>" + "</html>";

        try {
            send(client, sender, recipient, subject, bodyHTML);
            client.close();
            System.out.println("Done");

        } catch (MessagingException e) {
            e.getStackTrace();
        }
    }

    private void send(SesClient client,
            String sender,
            String recipient,
            String subject,
            String bodyHTML) throws MessagingException {

        Destination destination = Destination.builder()
                .toAddresses(recipient)
                .build();

        Content content = Content.builder()
                .data(bodyHTML)
                .build();

        Content sub = Content.builder()
                .data(subject)
                .build();

        Body body = Body.builder()
                .html(content)
                .build();

        Message msg = Message.builder()
                .subject(sub)
                .body(body)
                .build();

        SendEmailRequest emailRequest = SendEmailRequest.builder()
                .destination(destination)
                .message(msg)
                .source(sender)
                .build();

        try {
            System.out.println("Attempting to send an email through Amazon SES " + "using the AWS SDK for Java...");
            client.sendEmail(emailRequest);

        } catch (SesException e) {
            System.err.println(e.awsErrorDetails().errorMessage());
            System.exit(1);
        }
    }
}
