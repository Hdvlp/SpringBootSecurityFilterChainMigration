package com.securityfilterchainmigration.demo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.securityfilterchainmigration.demo.config.objects.Nutrition;
import com.securityfilterchainmigration.demo.config.objects.Personalities;
import com.securityfilterchainmigration.demo.service.TokenRegistryService;

import java.util.Date;
import java.util.Map;
import java.util.Objects;


public class JwtUtils {

    public static String generate(String subject, String issuer, long expirationTimeInMillis, Map<String, Object> customClaims) throws JOSEException {

        long millisecNow = System.currentTimeMillis();
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .issueTime(new Date(millisecNow))
                .expirationTime(new Date(millisecNow + expirationTimeInMillis));

        for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
            claimsSetBuilder.claim(entry.getKey(), entry.getValue());
        }

        JWTClaimsSet claimsSet = claimsSetBuilder.build();


        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);


        SignedJWT signedJWT = new SignedJWT(header, claimsSet);


        JWSSigner signer = new MACSigner(JwtConfig.getKey());


        signedJWT.sign(signer);


        return signedJWT.serialize();
    }



    public static void readAndHandleToken(String token, TokenRegistryService tokenRegistryService){

        if (Objects.equals(validateToken(token, tokenRegistryService),false)){
            return;
        }

        try{

            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();
            String subjectClaim = claimSet.getStringClaim("sub");

            ObjectMapper objectMapper = new ObjectMapper();

            String nutritionJson = signedJWT.getJWTClaimsSet().getStringClaim("nutrition");
            Nutrition nutrition = objectMapper.readValue(nutritionJson, Nutrition.class);

            String personalitiesJson = signedJWT.getJWTClaimsSet().getStringClaim("personalities");
            Personalities personalities = objectMapper.readValue(personalitiesJson, Personalities.class);
            
            if (Objects.equals(subjectClaim, null)){
                return;
            }
            if (Objects.equals(nutrition.toString(), null)){
                return;
            }
            if (Objects.equals(personalities.toString(), null)){
                return;
            }
  
            System.out.println("What claims are in JWT?");

            System.out.println(subjectClaim);
            System.out.println(nutrition.toString());
            System.out.println(personalities.toString());

        }catch (Exception e){}
    }


    public static boolean validateToken(String token, TokenRegistryService tokenRegistryService) {
        boolean isValid = false;
        if (Objects.equals(token, null)) {
            isValid = false;
            return isValid;
        }
        if (token.length() > JwtConfig.getJwtTokenValueLimit()){
                
            isValid = false;
            return isValid;
        }

        boolean isUsedPreviously = tokenRegistryService.isTokenUsedPreviously(token);

        if (Objects.equals(isUsedPreviously, true)){
            
            isValid = false;
            return isValid;
        }

        try {
            // Parse the JWT
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Extract claims
            String subject = signedJWT.getJWTClaimsSet().getSubject();
            String issuer = signedJWT.getJWTClaimsSet().getIssuer();
            if (!subject.equals(JwtConfig.getJwtClaimSubject())) {
                isValid = false;
                return isValid;
            }
            if (!issuer.equals(JwtConfig.getJwtClaimIssuer())) {
                isValid = false;
                return isValid;
            }

            isValid = true;
            return isValid;
        } catch (Exception e) {
            isValid = false;
        } finally {
            
        }
        return isValid;
    }

}
