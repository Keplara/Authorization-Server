package com.keplara.auth_service.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
public class OidcRequest {
    
    private List<String> scope;

    @JsonProperty("response_type")
    private String resposeType = "code";

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    private String state;
}
// once server gets sends code to client the client can request access token


//Session token
// {
//     "iss": "https://server.example.com",
//     "sub": "24400320",
//     "aud": "s6BhdRkqt3",
//     "nonce": "n-0S6_WzA2Mj",
//     "exp": 1311281970,
//     "iat": 1311280970,
//     "auth_time": 1311280969,
//     "acr": "urn:mace:incommon:iap:silver"
//     }




// POST /token HTTP/1.1
// Host: server.example.com
// Content-Type: application/x-www-form-urlencoded
// Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

// grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
//   &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb

// responds with
// id_token
// ID Token value associated with the authenticated session.
//Cache-Control	no-store header
// HTTP/1.1 200 OK
// Content-Type: application/json
// Cache-Control: no-store

// {
//  "access_token": "SlAV32hkKG",
//  "token_type": "Bearer",
//  "refresh_token": "8xLOxBtZp8",
//  "expires_in": 3600,
//  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzc
//    yI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5
//    NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZ
//    fV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5Nz
//    AKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6q
//    Jp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJ
//    NqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7Tpd
//    QyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoS
//    K5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4
//    XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg"
// }