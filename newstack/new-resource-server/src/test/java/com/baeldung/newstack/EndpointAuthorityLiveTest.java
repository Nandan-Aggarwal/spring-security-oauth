package com.baeldung.newstack;

import com.baeldung.newstack.web.dto.ProjectDto;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.http.HttpHeaders;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;


public class EndpointAuthorityLiveTest {
    private static final String RESOURCE_SERVER = "http://localhost:8081/new-resource-server";
    private static final String AUTHORIZATION_URI = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/auth";
    private static final String TOKEN_URI = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/token";
    private static final String CLIENT_ID = "newClient";
    private static final String CLIENT_SECRET = "newClientSecret";
    private static final String REDIRECT_URI = "http://localhost:8082/new-client/login/oauth2/code/custom";

    @Test
    public void createProject_usernameFromBaeldungDomain_returnsResponseCode201() {
        String bearerToken = fetchBearerToken("john@baeldung.com", "123");
        Assert.assertNotNull(bearerToken);

        ProjectDto projectDto = new ProjectDto(4l, "project_"+ UUID.randomUUID(), LocalDate.now());

        Response response = RestAssured.given().header("Authorization", "Bearer " + bearerToken).body(projectDto)
                                       .contentType(ContentType.JSON)
                                       .post(RESOURCE_SERVER + "/api/projects/");

        assertEquals(201, response.getStatusCode());
    }

    @Test
    public void createProject_usernameFromUnknownDomain_returnsResponseCode403() {
        String bearerToken = fetchBearerToken("mike@other.com", "pass");
        Assert.assertNotNull(bearerToken);
        ProjectDto projectDto = new ProjectDto(4l, "project_test", LocalDate.now());

        Response response = RestAssured.given().header("Authorization", "Bearer " + bearerToken).body(projectDto)
                                       .contentType(ContentType.JSON)
                                       .post(RESOURCE_SERVER + "/api/projects/");

        assertEquals(403, response.getStatusCode());
    }

    private String fetchBearerToken(String username, String password) {
        Response response = redirectToLoginScreen();

        response = submitLoginForm(username, password, response);

        String code = extractCodeAfterLogin(response);

        return fetchBearerTokenUsingCode(code);
    }

    private String fetchBearerTokenUsingCode(String code) {
        Map<String, String> tokenParams = new HashMap<String, String>();
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
        return redirectUrl.split("#|=|&")[3];
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
