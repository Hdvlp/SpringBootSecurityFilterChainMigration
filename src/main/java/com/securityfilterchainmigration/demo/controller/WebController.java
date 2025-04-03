package com.securityfilterchainmigration.demo.controller;

import org.springframework.web.bind.annotation.RestController;

import com.securityfilterchainmigration.demo.service.OAuth2ApiService;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;


@RestController
public class WebController {

    @Autowired
    OAuth2ApiService oAuth2ApiService;

    @GetMapping("/deny")
    public String denyContent() {
        return new String("You are _not_ permitted.");
    }

    @GetMapping("/public")
    public String publicContent() {
        return new String("Public.");
    }

    @GetMapping("/home")
    public String homeContent() {
        return new String("Home.");
    }

    @GetMapping("/home/callback")
    public String homeCallBackContent() {
        return new String("Home callback.");
    }

    @GetMapping("/permit")
    public String permitContent() {
        return new String("You are permitted.");
    }

    @GetMapping("/actuator/health/{service}")
    public String actuatorContent(@PathVariable final String service) {
        String[] services = {"servicea", "serviceb", "servicec", "serviced"};
        if (Arrays.asList(services).indexOf(service) == -1) return "";
        return String.format("actuator health of %s.", service);
    }

    @GetMapping("/member/area")
    public String memberContent() {
 
        return String.format(
                "<div>Member content. Part A. <a href=\"%s\">Log out</a></div><div><a href=\"%s\">Member Area Part B</a></div><div>%s</div>",
                "/logout",
                "/member/area/part/b",
                String.join(",", oAuth2ApiService.getEmails()) 
            );
    }

    @GetMapping("/member/area/part/b")
    public String memberAreaPageBContent() {
 
        return String.format(
                "<div>Member content. Part B. <a href=\"%s\">Log out</a></div><div><a href=\"%s\">Member Area Part A</a></div><div>%s</div>",
                "/logout",
                        "/member/area",
                String.join(",", oAuth2ApiService.getEmails()) 
            );
    }

}
