package com.keplara.auth_service.configuration.util;

import software.amazon.awssdk.services.sesv2.model.Template.Builder;

import software.amazon.awssdk.services.sesv2.model.Template;

public class SimpleEmailServiceTemplate {
    // Template: {
    //     TemplateName: "TEMPLATE_NAME" /* required */,
    //     HtmlPart: "HTML_CONTENT",
    //     SubjectPart: "SUBJECT_LINE",
    //     TextPart: "TEXT_CONTENT",
    //   },

    public Template getNoReplyTemplate(){
        Builder templateBuilder = Template.builder();
        return templateBuilder
        .templateName("no-reply")
        .templateData("{\n" +
                "  \"name\": \"Jason\"\n," +
                "  \"favoriteanimal\": \"Cat\"\n" +
                "}")
        .build();
    }

    public void createNoReplyEmailTemplate(){

    }
}
