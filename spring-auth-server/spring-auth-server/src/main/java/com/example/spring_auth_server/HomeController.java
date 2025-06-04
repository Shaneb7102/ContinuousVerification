package com.example.spring_auth_server;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController {

    @GetMapping("/login")
        @ResponseBody
        public String login(@RequestParam(required = false) String session) {
            if ("expired".equals(session)) {
                return "Session expired. Please log in again.";
            } else if ("anomaly".equals(session)) {
                return "Session anomaly detected (IP/User-Agent mismatch). Please re-authenticate.";
            } else if ("reauth".equals(session)) {
                return "Sensitive action detected. Please re-authenticate.";
            }
            return "Please log in.";
        }


    @GetMapping("/")
    @ResponseBody
    public String home(HttpSession session) {
        Object loginTime = session.getAttribute("loginTime");
        String formattedLoginTime = "unknown";

        if (loginTime instanceof Long) {
            java.text.SimpleDateFormat formatter =
                new java.text.SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z");
            formatter.setTimeZone(java.util.TimeZone.getTimeZone("GMT"));
            formattedLoginTime = formatter.format(new java.util.Date((Long) loginTime));
        }

        return "Welcome! You are logged in. Login time (GMT): " + formattedLoginTime;
    }

    @GetMapping("/sensitive")
        public String sensitive(HttpSession session) {
            session.invalidate();
            return "redirect:/login?reauth=true";
        }


    @GetMapping("/login-success")
    public String loginSuccess(HttpServletRequest request, HttpSession session) {
        request.changeSessionId(); // Regenerate session ID to prevent fixation
        session.setAttribute("loginTime", System.currentTimeMillis());
        session.setAttribute("ip", request.getRemoteAddr());
        session.setAttribute("ua", request.getHeader("User-Agent"));
        return "redirect:/";
    }


    @GetMapping("/secured")
    @ResponseBody
    public String secured() {
        return "This is a secured endpoint. You are authenticated.";
    }
}    
