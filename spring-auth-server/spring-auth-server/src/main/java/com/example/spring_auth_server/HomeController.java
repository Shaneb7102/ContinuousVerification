package com.example.spring_auth_server;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController {

    @GetMapping("/")
    @ResponseBody
    public String home(HttpSession session) {
        Object loginTime = session.getAttribute("loginTime");
        return "Welcome! You are logged in. Login time: " + (loginTime != null ? loginTime : "unknown");
    }

    @GetMapping("/login-success")
    public String loginSuccess(HttpSession session) {
        session.setAttribute("loginTime", System.currentTimeMillis());
        return "redirect:/";
    }

    @GetMapping("/secured")
    @ResponseBody
    public String secured() {
        return "This is a secured endpoint. You are authenticated.";
    }

    @GetMapping("/login")
    @ResponseBody
    public String loginPage() {
        return "<html><body><form method='post' action='/login'>" +
               "Username: <input type='text' name='username'/><br/>" +
               "Password: <input type='password' name='password'/><br/>" +
               "<input type='submit' value='Login'/></form></body></html>";
    }
}
