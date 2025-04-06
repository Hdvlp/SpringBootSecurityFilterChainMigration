package com.securityfilterchainmigration.demo.config;


import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class SecurityContextProvider {

    public SecurityContext getSecurityContext() {
        return SecurityContextHolder.getContext(); 
            // The SecurityContextHolder is where Spring Security 
            // stores the details of who is authenticated. 
            // Spring Security does not care how the SecurityContextHolder is populated. 
            // If it contains a value, it is used as the currently authenticated user.
            // 
            //
            // The SecurityContext is obtained from the SecurityContextHolder. 
            // The SecurityContext contains an Authentication object.
            //
            // Simply getting does _not_ cause a race condition.
            // 
            // https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html
    }



}