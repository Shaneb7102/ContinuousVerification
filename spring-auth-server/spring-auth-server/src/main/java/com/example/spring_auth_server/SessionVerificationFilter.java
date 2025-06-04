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
        HttpSession session = request.getSession(false);

        if (session != null && request.getRequestURI().startsWith("/secured")) {
            Long loginTime = (Long) session.getAttribute("loginTime");
            if (loginTime != null) {
                long now = System.currentTimeMillis();
                if (now - loginTime > MAX_SESSION_AGE_MS) {
                    session.invalidate();
                    ((HttpServletResponse) res).sendRedirect("/login?session=expired");
                    return;
                }
            }
        }

        chain.doFilter(req, res);
    }
}
