package com.example.spring_auth_server;


import jakarta.servlet.http.*;

class RiskScoringService {

    private final java.util.Map<String, VerificationStrategy> strategyMap = java.util.Map.of(
        "time", new TimeBasedVerification(),
        "ip", new SuspiciousIpVerification(),
        "freq", new FrequencyBasedVerification()
    );

    public int evaluateRisk(HttpServletRequest request, HttpSession session) {
        String[] methodParams = request.getParameterValues("methods");
        java.util.Set<String> activeMethods = (methodParams != null && methodParams.length > 0)
            ? java.util.Set.of(methodParams[0].split(","))
            : strategyMap.keySet(); // default to all if none specified

        AuditLoggerService.log("Active verification methods: " + String.join(", ", activeMethods));

        int totalRisk = 0;
        for (String methodKey : strategyMap.keySet()) {
        VerificationStrategy strategy = strategyMap.get(methodKey);
        if (strategy == null) continue;

        if (activeMethods.contains(methodKey)) {
            int risk = strategy.calculateRisk(request, session);
            System.out.println("[DEBUG] " + strategy.getName() + " returned risk: " + risk);
            totalRisk += risk;
        } else {
            System.out.println("[DEBUG] " + strategy.getName() + " was skipped");
        }
    }

        System.out.println("[DEBUG] TOTAL RISK SCORE: " + totalRisk);
        return totalRisk;
    }
}
