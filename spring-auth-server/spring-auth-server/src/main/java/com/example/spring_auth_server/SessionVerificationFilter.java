package com.example.spring_auth_server;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;

public class SessionVerificationFilter implements Filter {

    private static final long MAX_SESSION_AGE_MS = 10 * 1000; // 10 seconds

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

            // Validate IP and UA
            if (originalIp != null && originalUA != null) {
                boolean ipChanged = !originalIp.equals(request.getRemoteAddr());
                boolean uaChanged = !originalUA.equals(request.getHeader("User-Agent"));

                if (ipChanged || uaChanged) {
                    System.out.println("Anomaly detected: IP or User-Agent mismatch. Invalidating session.");
                    session.invalidate();
                    response.sendRedirect("/login?session=anomaly");
                    return;
                }
            }

            // Timeout verification
            if (loginTime != null) {
                long now = System.currentTimeMillis();
                if (now - loginTime > MAX_SESSION_AGE_MS) {
                    System.out.println("Session for user " + session.getId() + " expired due to timeout.");
                    session.invalidate();
                    response.sendRedirect("/login?session=expired");
                    return;
                }
            }
        }

        chain.doFilter(req, res);
    }
}

