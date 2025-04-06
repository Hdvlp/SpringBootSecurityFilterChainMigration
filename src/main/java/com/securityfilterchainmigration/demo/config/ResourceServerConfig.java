package com.securityfilterchainmigration.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig  {

    private JwtAuthenticationFilter jwtAuthenticationFilter;

    public ResourceServerConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    @Order(100)
    SecurityFilterChain securityFilterChainHelloWorld(HttpSecurity http) throws Exception {
        String[] matchedPaths = { "/public" };
        http
            .csrf(AbstractHttpConfigurer::disable)
            .securityMatcher(matchedPaths)
            .authorizeHttpRequests(
                auth -> 
                    auth
                    .requestMatchers(matchedPaths)
                    .permitAll()
            );

        return http.build();
    }

    @Bean
    @Order(200)
    SecurityFilterChain securityFilterChainHome(HttpSecurity http) throws Exception {
        String[] matchedPaths = { "/home" };
        http
            .csrf(AbstractHttpConfigurer::disable)
            .securityMatcher(matchedPaths)
            .authorizeHttpRequests(
                auth -> 
                    auth
                        .requestMatchers(matchedPaths)
                        .permitAll()
            );

        return http.build();
    }

    @Bean
    @Order(300)
    SecurityFilterChain securityFilterChainDenyAll(HttpSecurity http) throws Exception {
        String[] matchedPaths = { "/deny", "/deny/**" };
        http
            .csrf(AbstractHttpConfigurer::disable)
            .securityMatcher(matchedPaths)
            .authorizeHttpRequests(
                auth -> 
                    auth
                        .requestMatchers(matchedPaths)
                        .denyAll()
            );

        return http.build();
    }

    @Bean
    @Order(400)
    SecurityFilterChain securityFilterChainPermitAll(HttpSecurity http) throws Exception {
        String[] matchedPaths = { "/permit", "/permit/**" };
        http
            .csrf(AbstractHttpConfigurer::disable)
            .securityMatcher(matchedPaths)
            .authorizeHttpRequests(
                auth -> 
                    auth
                        .requestMatchers(matchedPaths)
                        .permitAll()
            );

        return http.build();
    }
    
    @Bean
    @Order(500)
    SecurityFilterChain securityFilterChainActuator(HttpSecurity http) throws Exception {
        String[] matchedPaths = { "/actuator/health/**" };
        http
            .csrf(AbstractHttpConfigurer::disable)
            .securityMatcher(matchedPaths)
            .authorizeHttpRequests(
                auth -> 
                    auth
                        .requestMatchers(matchedPaths)
                        .permitAll()
            );

        return http.build();
    }

    @Bean
    @Order(600)
    SecurityFilterChain securityFilterChainMemberArea(HttpSecurity http) throws Exception {
        String[] matchedPaths = { "/member/area", "/member/area/**" };
        http
            .csrf(AbstractHttpConfigurer::disable)
            .securityMatcher(matchedPaths)
            .authorizeHttpRequests( 
                auth -> 
                    auth.anyRequest().authenticated()
            );

        return http.build();
    }

    
    @Bean
    @Order(700)
    SecurityFilterChain securityFilterChainRequiresLogin(HttpSecurity http) throws Exception {
        String[] matchedPaths = { "/**" };
        http
                .csrf(AbstractHttpConfigurer::disable)
                .securityMatcher(matchedPaths)
                .authorizeHttpRequests(
                    auth -> auth
                                .requestMatchers(matchedPaths)
                                .hasAnyRole("GUEST", "USER")
                                .anyRequest()
                                .authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                
                .oauth2Client(Customizer.withDefaults())
                .oauth2Login(
                            oauth2Login -> oauth2Login
                            .successHandler(customAuthenticationSuccessHandler())
                            .defaultSuccessUrl("/member/area")

                            
                )
                        
                .formLogin(Customizer.withDefaults())

                .logout(logout -> logout
                    .logoutUrl("/logout")
                    .addLogoutHandler(customLogoutHandler())
                    .logoutSuccessHandler(customLogoutSuccessHandler())
                );

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler();
    }

    @Bean
    public CustomLogoutHandler customLogoutHandler() {
        return new CustomLogoutHandler();
    }

    @Bean
    public CustomLogoutSuccessHandler customLogoutSuccessHandler() {
        return new CustomLogoutSuccessHandler();
    }

}
