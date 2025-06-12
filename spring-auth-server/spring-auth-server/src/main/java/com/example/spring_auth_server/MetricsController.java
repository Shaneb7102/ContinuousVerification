package com.example.spring_auth_server;



import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MetricsController {

    private final RiskScoringService riskScoringService;

    public MetricsController(RiskScoringService riskScoringService) {
        this.riskScoringService = riskScoringService;
    }

    @GetMapping("/metrics")
    public String metrics() {
        StringBuilder sb = new StringBuilder();
        sb.append("<pre>\n=== Average Execution Times ===\n");

        for (String key : riskScoringService.getStrategyKeys()) {
            long total = riskScoringService.getTotalTime(key);
            int runs = riskScoringService.getCount(key);
            long avgNs = total / Math.max(runs, 1);
            double avgMs = avgNs / 1_000_000.0;
            sb.append(String.format("%s: %.3f ms (%d runs)\n", key, avgMs, runs));
        }

        sb.append("</pre>");
        return sb.toString();
    }
}

