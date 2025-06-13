package com.example.spring_auth_server;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;



class SessionVerificationFilter implements Filter {

    private static final long MAX_SESSION_AGE_MS = 500 * 1000;
    private final RiskScoringService riskScoringService;
    

    


    public SessionVerificationFilter(RiskScoringService riskScoringService) {
        this.riskScoringService = riskScoringService;
    }

    private final PolicyEnforcer policyEnforcer = new PolicyEnforcer();

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        HttpSession session = request.getSession(false);

        if (session != null && request.getRequestURI().startsWith("/secured")) {
            Long loginTime = (Long) session.getAttribute("loginTime");
            String originalIp = (String) session.getAttribute("ip");
            String originalUA = (String) session.getAttribute("ua");

            if (originalIp != null && originalUA != null) {

                // Check if IP or User-Agent has changed

                System.out.println("Stored User-Agent: " + originalUA);
                System.out.println("Request User-Agent: " + request.getHeader("User-Agent"));

                boolean ipChanged = !originalIp.equals(request.getRemoteAddr());
                boolean uaChanged = !originalUA.equals(request.getHeader("User-Agent"));

                

                if (ipChanged || uaChanged) {
                    AuditLoggerService.logReauthEvent(session, "IP or User-Agent anomaly detected");
                    session.invalidate();
                    response.sendRedirect("/login?session=anomaly");
                    return;
                }
            }

            if (loginTime != null) {
                long now = System.currentTimeMillis();
                if (now - loginTime > MAX_SESSION_AGE_MS) {
                    AuditLoggerService.logReauthEvent(session, "Session timeout");
                    session.invalidate();
                    response.sendRedirect("/login?session=expired");
                    return;
                }
            }
            int riskScore = riskScoringService.evaluateRisk(request, session);

            EnforcementDecision decision = policyEnforcer.evaluate(riskScore, request, session);

            switch (decision) {
                case REAUTHENTICATE -> {
                    AuditLoggerService.logReauthEvent(session, "Policy triggered reauthentication");
                    session.invalidate();
                    response.sendRedirect("/login?session=reauth");
                    return;
                }
                case BLOCK -> {
                    AuditLoggerService.logReauthEvent(session, "Policy blocked access");
                    session.invalidate();
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access blocked by policy");
                    return;
                }
                case ALERT_ONLY -> {
                    AuditLoggerService.logReauthEvent(session, "Policy alert only triggered");
                    // Allow to proceed
                }
                case ALLOW -> {
                    // No action needed
                }
            }

        }

        chain.doFilter(req, res);
    }
}
