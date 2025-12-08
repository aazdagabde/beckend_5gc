package com.free5gc.security_ids.service;

import com.free5gc.security_ids.model.LogEntry;
import com.free5gc.security_ids.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SecurityService {

    private final LogRepository logRepository;
    private final SimpMessagingTemplate messagingTemplate;

    // Liste Blanche (Mise à jour avec tous tes conteneurs)
    private static final List<String> KNOWN_NFS = Arrays.asList(
            "amf", "smf", "ausf", "udm", "pcf", "nrf", "upf", "nssf", "nef", "chf", "tngf", "n3iwf", "ueransim", "webui", "mongodb"
    );

    public LogEntry processLog(LogEntry log) {
        // 1. Détection
        detectAnomalies(log);

        // 2. Sauvegarde
        LogEntry savedLog = logRepository.save(log);

        // 3. Diffusion Temps Réel (Logs normaux)
        messagingTemplate.convertAndSend("/topic/logs", savedLog);

        return savedLog;
    }

    private void detectAnomalies(LogEntry log) {
        String msg = (log.getMessage() != null) ? log.getMessage().toLowerCase() : "";
        String nf = (log.getNfName() != null) ? log.getNfName().toLowerCase() : "unknown";
        String level = (log.getLevel() != null) ? log.getLevel() : "INFO";

        // =================================================================
        // 🛡️ MOTEUR DE RÈGLES IDS (5G Security Rules)
        // =================================================================

        // --- RÈGLE 1 : Auth Failure (AUSF/UDM) ---
        if ((nf.contains("ausf") || nf.contains("udm")) &&
                (msg.contains("authentication failed") || msg.contains("macfailure") || msg.contains("auth_failure"))) {
            triggerAlert(log, "AUTH_FAILURE", "MEDIUM");
        }

        // --- RÈGLE 2 : SMF Critical Crash (DoS) ---
        if (nf.contains("smf") && "ERROR".equalsIgnoreCase(level)) {
            triggerAlert(log, "SESSION_CRASH", "HIGH");
        }

        // --- RÈGLE 3 : QoS Tampering (PCF) ---
        // Détecte si un utilisateur essaie de modifier ses règles de qualité de service
        if (nf.contains("pcf") && (msg.contains("policy reject") || msg.contains("qos modification failed"))) {
            triggerAlert(log, "QOS_TAMPERING", "HIGH");
        }

        // --- RÈGLE 4 : Unauthorized Slice Access (NSSF) ---
        // Détecte si un utilisateur essaie d'accéder à une slice interdite (ex: NSSAI mismatch)
        if (nf.contains("nssf") && (msg.contains("nssai") || msg.contains("slice")) &&
                (msg.contains("forbidden") || msg.contains("not allowed") || msg.contains("reject"))) {
            triggerAlert(log, "SLICE_ATTACK", "CRITICAL");
        }

        // --- RÈGLE 5 : API Abuse (NEF) ---
        // Détecte les abus sur la passerelle d'exposition (Rate limit, accès non autorisé)
        if (nf.contains("nef") && (msg.contains("rate limit") || msg.contains("quota exceeded") || msg.contains("unauthorized"))) {
            triggerAlert(log, "API_ABUSE", "MEDIUM");
        }

        // --- RÈGLE 6 : Rogue NF (Composant Inconnu) ---
        boolean isKnown = KNOWN_NFS.stream().anyMatch(nf::contains);
        if (!isKnown && !nf.equals("unknown")) {
            triggerAlert(log, "ROGUE_NF_DETECTED", "CRITICAL");
        }

        // --- RÈGLE 7 : Network Congestion (Général) ---
        if (msg.contains("congestion") || msg.contains("buffer overflow") || msg.contains("no such device")) {
            triggerAlert(log, "NETWORK_CONGESTION", "LOW");
        }
    }

    private void triggerAlert(LogEntry log, String type, String severity) {
        log.setAlert(true);
        log.setAlertType(type);
        log.setSeverity(severity);

        System.err.println("🚨 [IDS ALERTE] " + type + " (" + severity + ") détecté sur " + log.getNfName());

        // Diffusion SPÉCIALE pour la pop-up rouge sur le Dashboard
        messagingTemplate.convertAndSend("/topic/alerts", log);
    }
}