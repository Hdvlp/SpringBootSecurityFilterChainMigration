package com.securityfilterchainmigration.demo.config;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import com.securityfilterchainmigration.demo.service.TokenRegistryService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class CustomLogoutHandler implements LogoutHandler {

    @Autowired
    private TokenRegistryService tokenRegistryService;

    @Autowired
    private CookiesUtils cookiesUtils;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        String jwtValue = cookiesUtils.getStringFromCookies(request, "jwt");
        if (Objects.equals(jwtValue, null)){
            return;
        }

        tokenRegistryService.addTokenToTokensUsedPreviously(jwtValue); 

        return;
    }
}