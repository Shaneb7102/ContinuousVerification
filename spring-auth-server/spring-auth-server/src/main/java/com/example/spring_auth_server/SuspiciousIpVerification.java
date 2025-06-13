package com.example.spring_auth_server;

import jakarta.servlet.http.*;

class SuspiciousIpVerification implements VerificationStrategy {

    private static final java.util.Set<String> suspiciousIps = java.util.Set.of("192.168.1.100", "10.0.0.66", "127.0.0.1");

    @Override
    public int calculateRisk(HttpServletRequest request, HttpSession session) {
        String ip = request.getRemoteAddr();
        return suspiciousIps.contains(ip) ? 5 : 0;
    }

    @Override
    public String getName() {
        return "Suspicious IP Verification";
    }
}
