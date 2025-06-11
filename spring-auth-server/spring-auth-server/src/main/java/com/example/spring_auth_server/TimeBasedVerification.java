package com.example.spring_auth_server;
import jakarta.servlet.http.*; 

class TimeBasedVerification implements VerificationStrategy {
    @Override
    public int calculateRisk(HttpServletRequest request, HttpSession session) {
        int hour = java.time.LocalDateTime.now().getHour();
        return (hour < 6 || hour > 22) ? 4 : 0;
    }

    @Override
    public String getName() {
        return "Time-Based Verification";
    }
}
