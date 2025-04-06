package com.securityfilterchainmigration.demo.service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Service;

import com.securityfilterchainmigration.demo.config.SecurityContextProvider;

@Service
public class OAuth2ApiService {
    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final GitHubEmailService gitHubEmailService;

    @Autowired
    private SecurityContextProvider securityContextProvider;

    public OAuth2ApiService(OAuth2AuthorizedClientManager authorizedClientManager,
        GitHubEmailService gitHubEmailService) {
        this.authorizedClientManager = authorizedClientManager;
        this.gitHubEmailService = gitHubEmailService;
    }

    public String fetchData() {
        SecurityContext context = securityContextProvider.getSecurityContext();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("my-client")
                .principal(context.getAuthentication())
                .build();

        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
                                                // Attempt to authorize or re-authorize (if required) 
                                                // the client identified by the provided clientRegistrationId. 
                                                //
                                                // Implementations must return null 
                                                // if authorization is not supported for the specified client, 
                                                // e.g. the associated OAuth2AuthorizedClientProvider(s) 
                                                // does not support the authorization grant type configured for the client.
                                                //
                                                // https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/oauth2/client/OAuth2AuthorizedClientManager.html#authorize(org.springframework.security.oauth2.client.OAuth2AuthorizeRequest)
    
        if (authorizedClient == null) {
            throw new IllegalStateException("Authorization failed");
        }

        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        return "Access Token: " + accessToken;
    } 

    public String getAccessToken() {

        SecurityContext context = securityContextProvider.getSecurityContext();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("github")
                .principal(context.getAuthentication())
                .build();
    
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

        if (authorizedClient == null) {
            throw new IllegalStateException("Failed to authorize client.");
        }

        return authorizedClient.getAccessToken().getTokenValue();
        
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
