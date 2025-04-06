package com.securityfilterchainmigration.demo.config;


import java.io.IOException;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.securityfilterchainmigration.demo.service.TokenRegistryService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // Notes: 
    //
    // OncePerRequestFilter:
    //     Filter base class that aims to guarantee a single execution per request dispatch, 
    //     on any servlet container. 
    //     It provides a doFilterInternal(jakarta.servlet.http.HttpServletRequest, 
    //     jakarta.servlet.http.HttpServletResponse, jakarta.servlet.FilterChain) method  
    //     with HttpServletRequest and HttpServletResponse arguments.
    //     https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/OncePerRequestFilter.html


    private final OAuth2AuthenticationSuccessHandler 
        oAuth2AuthenticationSuccessHandler = new OAuth2AuthenticationSuccessHandler();

    private static final String SECRET_KEY = JwtConfig.getKey();


    @Autowired
    private TokenRegistryService tokenRegistryService;

    @Autowired
    private SecurityContextProvider securityContextProvider;

    @Autowired
    private CookiesUtils cookiesUtils;

    SecretKey key = getSigningKey();


    public static SecretKey getSigningKey() {

        byte[] secretBytes = Base64.getDecoder().decode(SECRET_KEY);
        return new SecretKeySpec(secretBytes, "HmacSHA256");  
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
      

        String token =  cookiesUtils.getStringFromCookies(request, "jwt");

        JwtUtils.readAndHandleToken(token, tokenRegistryService);


        try {

            // Objective of the code below: Indicate a user is authenticated. 
            // Steps involved: Set the SecurityContextHolder.

            SecurityContext context = securityContextProvider.getSecurityContext();
            // (SecurityContextHolder Point 1) 
            // We start by creating a SecurityContext.
            //
            // SecurityContext - is obtained from the SecurityContextHolder 
            // and contains the Authentication of the currently authenticated user.
            //
            // `SecurityContextHolder.getContext().setAuthentication(authentication)`
            // is intentionally _not_ used to avoid race conditions.
            // (This is because getting _and_ setting like this can cause inconsistencies.)
            // https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-securitycontextholder
            
                
            Authentication auth = context.getAuthentication();

            if (auth != null){
                oAuth2AuthenticationSuccessHandler.onAuthenticationSuccess(
                    request, 
                    response,                                        
                    auth
                    );

                // The lines below avoided `SecurityContextHolder.getContext().setAuthentication(authentication)`,
                // thus avoiding race conditions of getting _and_ setting.
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(auth);
                SecurityContextHolder.setContext(securityContext);
                
                filterChain.doFilter(request, response);
                return;
    
            }





            boolean isValidToken = false;
            if (token != null){
                isValidToken = JwtUtils.validateToken(token, tokenRegistryService);
            }

            if (token != null && isValidToken == true) {


                // Notes:
                //
                // validateToken(token)
                // (SecurityContextHolder Point 2)
                // 
                // We create a new Authentication object. 
                // 
                // https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-securitycontextholder
                
                Authentication authJwt = getAuthentication(token);

                if (authJwt != null){


                    // The lines below avoided `SecurityContextHolder.getContext().setAuthentication(authentication)`,
                    // thus avoiding race conditions of getting _and_ setting.
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                    securityContext.setAuthentication(authJwt);
                    SecurityContextHolder.setContext(securityContext);

                    // (SecurityContextHolder Point 3)
                    // Finally, we set the SecurityContext on the SecurityContextHolder. 
                    // Spring Security uses this information for authorization.
                    // 
                    // https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-securitycontextholder



                    filterChain.doFilter(request, response);
                    return;

                }

            }


            // Keep this default filter chain when nothing above matches.
            // This is the default filter chain below. 
            filterChain.doFilter(request, response);
            return;
        }catch (Exception e){}
    }




    private Authentication getAuthentication(String token) {

        Collection<? extends GrantedAuthority> authoritiesDefault =
            Arrays.stream(new String[]{"USER"}) 
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

        UsernamePasswordAuthenticationToken authTok = new UsernamePasswordAuthenticationToken(
            JwtConfig.getJwtClaimSubject(), 
            token, 
            authoritiesDefault);
        return authTok;

        // Notes:
        //
        // UsernamePasswordAuthenticationToken(JwtConfig.getJwtClaimSubject(), token, authoritiesDefault)
        // This constructor should only be used by AuthenticationManager or 
        // AuthenticationProvider implementations that are satisfied with producing a trusted 
        // (i.e. AbstractAuthenticationToken.isAuthenticated() = true) authentication token.
        // https://docs.spring.io/spring-security/site/docs/4.0.x/apidocs/org/springframework/security/authentication/UsernamePasswordAuthenticationToken.html#UsernamePasswordAuthenticationToken-java.lang.Object-java.lang.Object-java.util.Collection-

    }

}