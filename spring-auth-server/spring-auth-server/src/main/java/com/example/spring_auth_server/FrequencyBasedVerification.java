package com.example.spring_auth_server;
import jakarta.servlet.http.*;

class FrequencyBasedVerification implements VerificationStrategy {

    private final java.util.Map<String, java.util.List<Long>> accessLog = new java.util.concurrent.ConcurrentHashMap<>();

    @Override
    public int calculateRisk(HttpServletRequest request, HttpSession session) {
        String ip = request.getRemoteAddr();
        long now = System.currentTimeMillis();

        accessLog.putIfAbsent(ip, new java.util.ArrayList<>());
        var timestamps = accessLog.get(ip);
        timestamps.add(now);
        timestamps.removeIf(ts -> now - ts > 60_000);

        return (timestamps.size() > 10) ? 3 : 0;
    }

    @Override
    public String getName() {
        return "Frequency-Based Verification";
    }
}
