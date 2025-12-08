package com.free5gc.security_ids.service;

import com.free5gc.security_ids.model.LogEntry;
import com.free5gc.security_ids.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate; // <--- IMPORT IMPORTANT
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SecurityService {

    private final LogRepository logRepository;
    private final SimpMessagingTemplate messagingTemplate; // <--- Injection du WebSocket

    // Liste Blanche
    private static final List<String> KNOWN_NFS = Arrays.asList(
            "amf", "smf", "ausf", "udm", "pcf", "nrf", "upf", "nssf", "nef", "ueransim", "webui", "mongodb"
    );

    public LogEntry processLog(LogEntry log) {
        // 1. Détection
        detectAnomalies(log);

        // 2. Sauvegarde
        LogEntry savedLog = logRepository.save(log);

        // 3. (NOUVEAU) Diffusion Temps Réel
        // On envoie TOUS les logs au dashboard pour l'affichage "Live Logs"
        messagingTemplate.convertAndSend("/topic/logs", savedLog);

        return savedLog;
    }

    private void detectAnomalies(LogEntry log) {
        String msg = (log.getMessage() != null) ? log.getMessage().toLowerCase() : "";
        String nf = (log.getNfName() != null) ? log.getNfName().toLowerCase() : "unknown";
        String level = (log.getLevel() != null) ? log.getLevel() : "INFO";

        // --- RÈGLES DE DÉTECTION ---

        // Règle 1 : Auth Failure
        if ((nf.contains("ausf") || nf.contains("udm")) &&
                (msg.contains("authentication failed") || msg.contains("macfailure") || msg.contains("auth_failure"))) {
            triggerAlert(log, "AUTH_FAILURE", "MEDIUM");
        }

        // Règle 2 : SMF Crash
        if (nf.contains("smf") && "ERROR".equalsIgnoreCase(level)) {
            triggerAlert(log, "SESSION_CRASH", "HIGH");
        }

        // Règle 3 : Rogue NF
        boolean isKnown = KNOWN_NFS.stream().anyMatch(nf::contains);
        if (!isKnown && !nf.equals("unknown")) {
            triggerAlert(log, "ROGUE_NF_DETECTED", "CRITICAL");
        }

        // Règle 4 : Congestion
        if (msg.contains("congestion") || msg.contains("no such device")) {
            triggerAlert(log, "NETWORK_CONGESTION", "LOW");
        }
    }

    private void triggerAlert(LogEntry log, String type, String severity) {
        log.setAlert(true);
        log.setAlertType(type);
        log.setSeverity(severity);

        System.err.println("🚨 [IDS ALERTE] " + type + " (" + severity + ") détecté sur " + log.getNfName());

        // (NOUVEAU) On envoie une notification SPÉCIALE sur le canal "/topic/alerts"
        // Le Frontend pourra afficher une pop-up ou jouer un son juste en écoutant ce canal
        messagingTemplate.convertAndSend("/topic/alerts", log);
    }
}