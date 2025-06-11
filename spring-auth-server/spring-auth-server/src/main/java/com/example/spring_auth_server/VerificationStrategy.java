package com.example.spring_auth_server;

import jakarta.servlet.http.*;

interface VerificationStrategy {
    int calculateRisk(HttpServletRequest request, HttpSession session);
    String getName();
}
