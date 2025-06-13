package com.example.spring_auth_server;

public enum EnforcementDecision {
    ALLOW,
    REAUTHENTICATE,
    BLOCK,
    ALERT_ONLY
}
