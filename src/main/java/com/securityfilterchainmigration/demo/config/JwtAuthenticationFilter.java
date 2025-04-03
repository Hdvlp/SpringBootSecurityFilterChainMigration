package com.securityfilterchainmigration.demo.config;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final OAuth2AuthenticationSuccessHandler 
        oAuth2AuthenticationSuccessHandler = new OAuth2AuthenticationSuccessHandler();

    private static final String SECRET_KEY = JwtConfig.getKey();
 

    SecretKey key = getSigningKey();
    public static SecretKey getSigningKey() {

        byte[] secretBytes = Base64.getDecoder().decode(SECRET_KEY);
        return new SecretKeySpec(secretBytes, "HmacSHA256");  
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
      
        try {


            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                String token = resolveToken(request);
                

                if (token != null && validateToken(token)) {

                    Authentication authentication = getAuthentication(token);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }

                filterChain.doFilter(request, response);
                return;
            }
                                            
            oAuth2AuthenticationSuccessHandler.onAuthenticationSuccess(
                request, 
                response,                                        
                SecurityContextHolder.getContext().getAuthentication()
                );


            String token = resolveToken(request);

            if (token != null && validateToken(token)) {

                
                Authentication authentication = getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);
        }catch (Exception _){}
    }

    private String resolveToken(HttpServletRequest request) {

        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {

        try {
            Jwts           
                .parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static Claims parseToken(String token) {

        SecretKey key = getSigningKey();
        return Jwts
            .parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    private Authentication getAuthentication(String token) {

        Claims claims = parseToken(token);

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("roles").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                        

        return new UsernamePasswordAuthenticationToken(claims.getSubject(), token, authorities);
    }

}