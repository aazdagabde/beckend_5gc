package com.free5gc.security_ids.service;

import com.free5gc.security_ids.model.LogEntry;
import com.free5gc.security_ids.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class SecurityService {

    private final LogRepository logRepository;
    private final SimpMessagingTemplate messagingTemplate;

    // Liste Blanche exacte (Doit correspondre aux noms dans Python)
    private static final List<String> KNOWN_NFS = Arrays.asList(
            "amf", "smf", "ausf", "udm", "pcf", "nrf", "upf", "nssf", "nef", "chf",
            "tngf", "n3iwf", "ueransim", "webui", "mongodb", "kafka", "zookeeper"
    );

    // Mémoire pour le Brute Force
    private final Map<String, Integer> authFailureCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAuthFailureTimestamps = new ConcurrentHashMap<>();

    public LogEntry processLog(LogEntry log) {
        // 1. DÉTECTION
        detectAnomalies(log);

        // 2. SAUVEGARDE
        LogEntry savedLog = logRepository.save(log);

        // 3. DIFFUSION WEBSOCKET
        // Canal général (Logs)
        messagingTemplate.convertAndSend("/topic/logs", savedLog);

        // Canal Alertes (Uniquement si attaque)
        if (savedLog.isAlert()) {
            System.out.println("🚨 ALERTE ENVOYÉE AU FRONT : " + savedLog.getAlertType());
            messagingTemplate.convertAndSend("/topic/alerts", savedLog);
        }

        return savedLog;
    }

    private void detectAnomalies(LogEntry log) {
        // Protection contre les nulls
        String msg = (log.getMessage() != null) ? log.getMessage().toLowerCase() : "";
        String nf = (log.getNfName() != null) ? log.getNfName().toLowerCase() : "unknown";
        String level = (log.getLevel() != null) ? log.getLevel().toUpperCase() : "INFO";

        // --- RÈGLE 1 : Brute Force (AUSF/UDM) ---
        if (msg.contains("authentication failed") || msg.contains("auth_failure") || msg.contains("macfailure")) {
            handleBruteForceDetection(log, nf);
        }

        // --- RÈGLE 2 : SMF Critical Crash (DoS) ---
        else if (nf.contains("smf") && (level.equals("ERROR") || msg.contains("critical service failure") || msg.contains("memory overflow"))) {
            triggerAlert(log, "DoS ATTACK (SMF Crash)", "HIGH");
        }

        // --- RÈGLE 3 : QoS Tampering (PCF) ---
        else if (nf.contains("pcf") && (msg.contains("policy reject") || msg.contains("qos modification failed"))) {
            triggerAlert(log, "QoS TAMPERING (Integrity)", "MEDIUM");
        }

        // --- RÈGLE 4 : Unauthorized Slice Access (NSSF) ---
        else if (nf.contains("nssf") && (msg.contains("slice") || msg.contains("nssai")) && (msg.contains("forbidden") || msg.contains("not allowed"))) {
            triggerAlert(log, "UNAUTHORIZED SLICE ACCESS", "CRITICAL");
        }

        // --- RÈGLE 5 : API Abuse (NEF) ---
        else if (nf.contains("nef") && (msg.contains("rate limit") || msg.contains("quota exceeded"))) {
            triggerAlert(log, "API ABUSE (Rate Limit)", "LOW");
        }

        // --- RÈGLE 6 : Rogue NF (Composant Inconnu) ---
        // Si la NF n'est pas dans la liste blanche ET n'est pas "unknown" (cas d'erreur de parsing)
        else if (!KNOWN_NFS.contains(nf) && !nf.equals("unknown")) {
            triggerAlert(log, "ROGUE NF DETECTED", "CRITICAL");
        }

        // --- RÈGLE 7 : Network Congestion ---
        else if (msg.contains("buffer overflow") || msg.contains("congestion")) {
            triggerAlert(log, "NETWORK CONGESTION", "LOW");
        }
    }

    private void handleBruteForceDetection(LogEntry log, String nf) {
        long currentTime = System.currentTimeMillis();
        long lastTime = lastAuthFailureTimestamps.getOrDefault(nf, 0L);
        int count = authFailureCounts.getOrDefault(nf, 0);

        // Reset du compteur si plus de 10 secondes entre deux échecs
        if (currentTime - lastTime > 10000) {
            count = 0;
        }

        count++;
        lastAuthFailureTimestamps.put(nf, currentTime);

        // SEUIL : 3 échecs
        if (count >= 3) {
            triggerAlert(log, "BRUTE FORCE DETECTED", "HIGH");

            // CORRECTION IMPORTANTE : On remet le compteur à 0 pour ne pas alerter 3 fois de suite
            count = 0;
        }

        // Sauvegarde du nouveau compte
        authFailureCounts.put(nf, count);
    }

    private void triggerAlert(LogEntry log, String type, String severity) {
        log.setAlert(true);
        log.setAlertType(type);
        log.setSeverity(severity);
    }
}