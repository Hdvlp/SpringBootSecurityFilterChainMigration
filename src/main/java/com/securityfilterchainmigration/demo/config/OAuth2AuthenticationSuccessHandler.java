package com.securityfilterchainmigration.demo.config;

import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityfilterchainmigration.demo.config.objects.Nutrition;
import com.securityfilterchainmigration.demo.config.objects.Personalities;

import org.springframework.security.oauth2.core.user.OAuth2User;
import jakarta.servlet.http.Cookie;
import java.util.Map;


public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    public OAuth2AuthenticationSuccessHandler(){}

    @Override
    public void onAuthenticationSuccess(
        jakarta.servlet.http.HttpServletRequest request, 
        jakarta.servlet.http.HttpServletResponse response, 
        org.springframework.security.core.Authentication authentication) 
            throws java.io.IOException,
                jakarta.servlet.ServletException
    {
        
        try{

            if (authentication.getPrincipal() instanceof OAuth2User) {
                
                //OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

                //System.out.println(oAuth2User);

                // Add custom claims to the JWT token:

                ObjectMapper objectMapper = new ObjectMapper();
                Nutrition nutrition = new Nutrition();
                String nutritionJson = objectMapper.writeValueAsString(nutrition);

                Personalities personalities = new Personalities();
                String personalitiesJson = objectMapper.writeValueAsString(personalities);


                Map.Entry<String, Object> nutritionMap = Map.entry(
                    "nutrition", 
                    nutritionJson);
                Map.Entry<String, Object> personalitiesMap = Map.entry(
                    "personalities", 
                    personalitiesJson);
                String jwt = JwtUtils.generate(
                    JwtConfig.getJwtClaimSubject(), 
                    JwtConfig.getJwtClaimIssuer(), 
                    JwtConfig.getJwtExpiryTimeMilliseconds(),
                    Map.ofEntries(nutritionMap, personalitiesMap));

                Cookie cookie = new Cookie("jwt", jwt);
                cookie.setHttpOnly(true);
                cookie.setSecure(true); // Set to true in production (requires HTTPS)
                cookie.setPath("/");
                cookie.setMaxAge(JwtConfig.getJwtExpiryTimeSeconds()); 

                response.addCookie(cookie);

            }

        }catch(Exception _){}

    }

}
