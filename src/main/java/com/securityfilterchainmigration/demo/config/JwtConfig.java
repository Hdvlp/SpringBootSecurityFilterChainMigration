package com.securityfilterchainmigration.demo.config;

public class JwtConfig {
    private static final String SECRET_KEY = "YourSecretKeyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    
    private static final String JWT_CLAIM_SUBJECT = "migration-app-example-subject";
    private static final String JWT_CLAIM_ISSUER = "migration-app-example-issuer";

    private static final int JWT_TOKEN_VALUE_LIMIT = 4096;
    
    private static final int EXPIRY_TIME_MILLISECONDS = 300000; 
                                                     // 30000 means 30 seconds
                                                     // 300000 means 300 seconds
    private static final int EXPIRY_TIME_SECONDS = EXPIRY_TIME_MILLISECONDS / 1000;

    public static String getKey(){
        return SECRET_KEY;
    }

    public static int getJwtExpiryTimeMilliseconds(){
        return EXPIRY_TIME_MILLISECONDS;
    }

    public static int getJwtExpiryTimeSeconds(){
        return EXPIRY_TIME_SECONDS;
    }

    public static int getJwtTokenValueLimit(){
        return JWT_TOKEN_VALUE_LIMIT;
    }

    public static String getJwtClaimSubject(){
        return JWT_CLAIM_SUBJECT;
    }

    public static String getJwtClaimIssuer(){
        return JWT_CLAIM_ISSUER;
    }
}
