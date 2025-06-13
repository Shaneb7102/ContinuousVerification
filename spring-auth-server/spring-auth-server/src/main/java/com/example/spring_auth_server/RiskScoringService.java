package com.example.spring_auth_server;



import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.*;

class RiskScoringService {

    private final java.util.Map<String, VerificationStrategy> strategyMap = java.util.Map.of(
        "time", new TimeBasedVerification(),
        "ip", new SuspiciousIpVerification(),
        "freq", new FrequencyBasedVerification()
    );

    private final Map<String, Long> totalTimeNs = new HashMap<>();
    private final Map<String, Integer> count = new HashMap<>();

    public int evaluateRisk(HttpServletRequest request, HttpSession session) {
        String[] methodParams = request.getParameterValues("methods");
        Set<String> activeMethods = (methodParams != null && methodParams.length > 0)
            ? Set.of(methodParams[0].split(","))
            : strategyMap.keySet(); // default to all if none specified

        int totalRisk = 0;
        for (String methodKey : strategyMap.keySet()) {
            if (!activeMethods.contains(methodKey)) continue;
            VerificationStrategy strategy = strategyMap.get(methodKey);

            long start = System.nanoTime();
            int risk = strategy.calculateRisk(request, session);
            long end = System.nanoTime();
            long elapsed = end - start;

            // Log and track timing
            totalTimeNs.merge(methodKey, elapsed, Long::sum);
            count.merge(methodKey, 1, Integer::sum);

            System.out.println("[TIME] " + strategy.getName() + " took " + elapsed + " ns");
            if (risk > 0) {
                System.out.println("[RISK] " + strategy.getName() + " → " + risk);
            }
            totalRisk += risk;
        }

        return totalRisk;
    }

    public void printAverageTimes() {
    System.out.println("\n=== Average Execution Times ===");
    for (String key : totalTimeNs.keySet()) {
        long total = totalTimeNs.get(key);
        int runs = count.getOrDefault(key, 1); // avoid div by zero
        long avgNs = total / runs;
        double avgMs = avgNs / 1_000_000.0;
        System.out.println(key + ": " + avgMs + " ms (" + runs + " runs)");
    }
}

public Set<String> getStrategyKeys() {
    return totalTimeNs.keySet();
}

public long getTotalTime(String key) {
    return totalTimeNs.getOrDefault(key, 0L);
}

public int getCount(String key) {
    return count.getOrDefault(key, 0);
}



}
