package com.securityfilterchainmigration.demo.config;


import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.IOException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;


public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final String SECRET_KEY = JwtConfig.getKey();

    public OAuth2AuthenticationSuccessHandler(){}

    @Override
    public void onAuthenticationSuccess(
        jakarta.servlet.http.HttpServletRequest request, 
        jakarta.servlet.http.HttpServletResponse response, 
        org.springframework.security.core.Authentication authentication) 
            throws IOException,
            jakarta.servlet.ServletException
    {
        
        try{

            if (authentication.getPrincipal() instanceof OAuth2User) {
                
                //OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

                //String name = oAuth2User.getAttribute("name"); 
                    // may or may not work
                    // depending on the format of the data
                //String email = oAuth2User.getAttribute("email");

                String jwt = generateJwt(authentication);

                Cookie cookie = new Cookie("jwt", jwt);
                cookie.setHttpOnly(true);
                cookie.setSecure(true); // Set to true in production (requires HTTPS)
                cookie.setPath("/");
                cookie.setMaxAge(JwtConfig.getJwtExpiryTimeSeconds()); // 1 hour expiration

                response.addCookie(cookie);

            }

        }catch(Exception _){}

    }

    private String generateJwt(Authentication authentication) {

        if (authentication == null) return null;

        SecretKey signingKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

        Claims claims = Jwts.claims().subject(authentication.getName()).build();

        return Jwts.builder()
                .claims(claims)
                .subject("migration-app-example-subject")
                .issuer("migration-app-example-issuer")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + JwtConfig.getJwtExpiryTimeMilliseconds())) 
                .signWith(signingKey)
                .compact();
    }
}
