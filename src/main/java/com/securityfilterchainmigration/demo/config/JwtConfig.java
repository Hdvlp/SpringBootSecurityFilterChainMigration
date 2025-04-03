package com.securityfilterchainmigration.demo.config;

public class JwtConfig {
    private static final String SECRET_KEY = "YourSecretKeyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    private static final int EXPIRY_TIME_MILLISECONDS = 3600000;
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
}
