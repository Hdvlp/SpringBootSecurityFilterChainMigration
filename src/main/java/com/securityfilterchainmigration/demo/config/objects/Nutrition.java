package com.securityfilterchainmigration.demo.config.objects;

public class Nutrition {
    public String[] nutrition = new String[]{"vitamin A", "carbohydrate"};
    public String toString(){
        return String.join("|", nutrition);
    }
}
