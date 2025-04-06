package com.securityfilterchainmigration.demo.config.objects;

public class Personalities {
    public String[] personalities = new String[]{"active", "outgoing"};
    public String toString(){
        return String.join("|", personalities);
    }
}
