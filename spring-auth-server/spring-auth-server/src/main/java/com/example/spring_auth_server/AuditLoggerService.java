package com.example.spring_auth_server;


import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import jakarta.servlet.http.HttpSession;



class AuditLoggerService {
    private static final String AUDIT_LOG_PATH = "audit.log";

    public static void log(String message) {
        try (PrintWriter out = new PrintWriter(new FileWriter(AUDIT_LOG_PATH, true))) {
            out.println(LocalDateTime.now() + " - " + message);
        } catch (IOException e) {
            System.err.println("Failed to write to audit log: " + e.getMessage());
        }
    }

    public static void logReauthEvent(HttpSession session, String reason) {
        String sessionId = (session != null) ? session.getId() : "unknown";
        log("Reauthentication triggered for session " + sessionId + ": " + reason);
    }
}