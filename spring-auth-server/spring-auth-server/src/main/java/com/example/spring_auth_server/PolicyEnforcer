package com.example.spring_auth_server;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

public class PolicyEnforcer {

    public EnforcementDecision evaluate(int riskScore, HttpServletRequest request, HttpSession session) {
        String uri = request.getRequestURI();

        // Example: Always reauthenticate on sensitive endpoints
        if (uri.contains("/sensitive")) {
            return EnforcementDecision.REAUTHENTICATE;
        }

        // High risk — block completely
        if (riskScore > 10) {
            return EnforcementDecision.BLOCK;
        }

        // Medium risk — force reauth
        if (riskScore > 5) {
            return EnforcementDecision.REAUTHENTICATE;
        }

        // Low risk — allow access
        if (riskScore > 2) {
            return EnforcementDecision.ALERT_ONLY;
        }

        return EnforcementDecision.ALLOW;
    }
}
