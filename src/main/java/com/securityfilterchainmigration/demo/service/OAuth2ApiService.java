package com.securityfilterchainmigration.demo.service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Service;

@Service
public class OAuth2ApiService {
    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final GitHubEmailService gitHubEmailService;

    public OAuth2ApiService(OAuth2AuthorizedClientManager authorizedClientManager,
        GitHubEmailService gitHubEmailService) {
        this.authorizedClientManager = authorizedClientManager;
        this.gitHubEmailService = gitHubEmailService;
    }

    public String fetchData() {
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("my-client")
                .principal(SecurityContextHolder.getContext().getAuthentication())
                .build();

        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

        if (authorizedClient != null) {
            String accessToken = authorizedClient.getAccessToken().getTokenValue();

            return "Access Token: " + accessToken;
        } else {
            throw new IllegalStateException("Authorization failed");
        }
    }

    public String getAccessToken() {

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("github")
                .principal(SecurityContextHolder.getContext().getAuthentication())
                .build();
    
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
    
        if (authorizedClient != null) {

            return authorizedClient.getAccessToken().getTokenValue();
        } else {
            throw new IllegalStateException("Failed to authorize client.");
        }
    }

    public List<Map<String, Object>> getEmailsObject(){
        String accessToken = this.getAccessToken();
        List<Map<String, Object>> emails = gitHubEmailService.fetchUserEmails(accessToken);
        return emails;
    }

    public List<String> getEmails(){
        List<Map<String, Object>> emailsObject = this.getEmailsObject();

        List<String> result = emailsObject.stream()
            .flatMap(map -> map.entrySet().stream())
            .filter(entry -> entry.getKey().equals("email"))
            .map(entry -> entry.getValue().toString())
            .collect(Collectors.toList());

        return result;
    }


}
