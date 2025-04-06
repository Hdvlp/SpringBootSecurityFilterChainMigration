package com.securityfilterchainmigration.demo.service;

import org.springframework.stereotype.Service;
import java.util.LinkedHashSet;

@Service
public class TokenRegistryService {
    private static final LinkedHashSet<String> tokensUsedPreviously = new LinkedHashSet<>(20, 3);
    
    public void addTokenToTokensUsedPreviously(String token) {
        tokensUsedPreviously.add(token);
    }

    public boolean isTokenUsedPreviously(String token) {
        // To deny access when using the _same_ token,
        // this method returns false when
        // the token is found in LinkedHashSet<String> tokensUsedPreviously.

        return tokensUsedPreviously.contains(token);
            // .contains
            //
            // Returns true if this set contains the specified element.
            // https://docs.oracle.com/javase/8/docs/api/index.html?java/util/LinkedHashSet.html
    }
}

