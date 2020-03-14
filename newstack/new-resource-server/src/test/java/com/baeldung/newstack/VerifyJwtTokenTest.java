package com.baeldung.newstack;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.http.HttpHeaders;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;


public class VerifyJwtTokenTest {
    private static final String RESOURCE_SERVER = "http://localhost:8081/new-resource-server";
    private static final String AUTHORIZATION_URI = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/auth";
    private static final String TOKEN_URI = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/token";
    private static final String CLIENT_ID = "newClient";
    private static final String CLIENT_SECRET = "newClientSecret";
    private static final String REDIRECT_URI = "http://localhost:8082/new-client/login/oauth2/code/custom";

    @Test
    public void verifyPreferredUsername_usernameFromBaeldungDomain_returnsResponseCode200() {
        String bearerToken = fetchBearerToken("john@baeldung.com", "123");
        Assert.assertNotNull(bearerToken);

        int httpStatus = RestAssured.given().header("Authorization", "Bearer " + bearerToken)
                   .get(RESOURCE_SERVER + "/api/projects").getStatusCode();
        assertEquals(200, httpStatus);
    }

    @Test
    public void verifyPreferredUsername_usernameFromUnknownDomain_returnsResponseCode401() {
        String bearerToken = fetchBearerToken("mike@other.com", "pass");
        Assert.assertNotNull(bearerToken);

        int httpStatus = RestAssured.given().header("Authorization", "Bearer " + bearerToken)
                                    .get(RESOURCE_SERVER + "/api/projects").getStatusCode();
        assertEquals(401, httpStatus);
    }

    private String fetchBearerToken(String username, String password) {
        Response response = redirectToLoginScreen();

        response = submitLoginForm(username, password, response);

        String code = extractCodeAfterLogin(response);

        return fetchBearerTokenUsingCode(code);
    }

    private String fetchBearerTokenUsingCode(String code) {
        Map<String, String> tokenParams = new HashMap<>();
        tokenParams.put("grant_type", "authorization_code");
        tokenParams.put("client_id", CLIENT_ID);
        tokenParams.put("client_secret", CLIENT_SECRET);
        tokenParams.put("redirect_uri", REDIRECT_URI);
        tokenParams.put("code", code);

        return RestAssured.given().formParams(tokenParams)
                              .post(TOKEN_URI).jsonPath().getString("access_token");

    }

    private String extractCodeAfterLogin(Response response) {
        String redirectUrl = response.getHeader(HttpHeaders.LOCATION);
        return redirectUrl.split("[#=&]")[3];
    }

    private Response submitLoginForm(String username, String password,Response response) {
        String formActionUrl = response.htmlPath().getString("'**'.find{node -> node.name()=='form'}*.@action");

        Map<String, String> formFields = new HashMap<>();
        formFields.put("username", username);
        formFields.put("password", password);
        return RestAssured.given().cookie("AUTH_SESSION_ID", response.getCookie("AUTH_SESSION_ID"))
                              .formParams(formFields)
                              .post(formActionUrl);

    }

    private Response redirectToLoginScreen() {
        Map<String, String> redirectUrlParams = new HashMap<>();
        redirectUrlParams.put("response_type", "code");
        redirectUrlParams.put("client_id", CLIENT_ID);
        redirectUrlParams.put("redirect_uri", REDIRECT_URI);
        redirectUrlParams.put("scope", "openid read write");
        return RestAssured.given().formParams(redirectUrlParams).get(AUTHORIZATION_URI);
    }
}
