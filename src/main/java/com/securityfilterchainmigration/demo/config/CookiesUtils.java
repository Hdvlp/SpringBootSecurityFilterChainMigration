package com.securityfilterchainmigration.demo.config;

import org.springframework.context.annotation.Configuration;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class CookiesUtils {

    public String getStringFromCookies(HttpServletRequest request, String name){
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (name.equals(cookie.getName())) { 
                    String cookieValueOfToken = cookie.getValue(); 
                    return cookieValueOfToken;
                }
            }
        }
        return null;
    }

}
