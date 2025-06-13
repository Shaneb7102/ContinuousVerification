package com.example.spring_auth_server;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import java.text.SimpleDateFormat;
import java.util.logging.Logger;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.TimeZone;
import java.util.Date;
@Controller
class HomeController {

    private static final Logger logger = Logger.getLogger(HomeController.class.getName());

    @GetMapping("/login")
    @ResponseBody
    public String login(@RequestParam(required = false) String session) {
        if ("expired".equals(session)) {
            return "Session expired. Please log in again.";
        } else if ("anomaly".equals(session)) {
            return "Session anomaly detected (IP/User-Agent mismatch). Please re-authenticate.";
        } else if ("reauth".equals(session)) {
            return "Sensitive action detected. Please re-authenticate.";
        } else if ("risk".equals(session)) {
            return "High-risk activity detected. Please re-authenticate.";
        }
        return "Please log in.";
    }

    @GetMapping("/")
    @ResponseBody
    public String home(HttpSession session) {
        Object loginTime = session.getAttribute("loginTime");
        String formattedLoginTime = "unknown";
        if (loginTime instanceof Long) {
            SimpleDateFormat formatter = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z");
            formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
            formattedLoginTime = formatter.format(new Date((Long) loginTime));
        }
        logger.info("Accessed home page at: " + formattedLoginTime);
        return "Welcome! You are logged in. Login time (GMT): " + formattedLoginTime;
    }

    @GetMapping("/reauth")
    @ResponseBody
    public String reauth(HttpSession session) {
        session.invalidate();
        return "You have been re-authenticated. Please log in again.";
    }

    @GetMapping("/sensitive")
    public String sensitive(HttpSession session) {
        logger.warning("Sensitive endpoint accessed. Triggering reauthentication.");
        session.invalidate();
        return "redirect:/login?reauth=true";
    }

    @GetMapping("/login-success")
    public String loginSuccess(HttpServletRequest request, HttpSession session) {
        if (session.getAttribute("pendingInvalidation") != null) {
        session.invalidate();
        return "redirect:/login?session=expired"; // or just force re-login
    }
    
        request.changeSessionId();
        session.setAttribute("loginTime", System.currentTimeMillis());
        session.setAttribute("ip", request.getRemoteAddr());
        session.setAttribute("ua", request.getHeader("User-Agent"));
        logger.info("Login successful from IP: " + request.getRemoteAddr());
        return "redirect:/";
    }

    @GetMapping("/secured")
    @ResponseBody
    public String secured(HttpServletRequest request) {
        logger.info("Accessed secured endpoint from IP: " + request.getRemoteAddr());
        return "This is a secured endpoint. You are authenticated.";
    }
}