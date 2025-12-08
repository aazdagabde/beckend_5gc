package com.free5gc.security_ids.controller;

import com.free5gc.security_ids.model.LogEntry;
import com.free5gc.security_ids.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Arrays;

@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class LogController {

    private final LogRepository logRepository;
    private final SimpMessagingTemplate messagingTemplate;

    // Liste des NFs légitimes (Liste blanche)
    private static final List<String> VALID_NFS = Arrays.asList("AMF", "SMF", "AUSF", "UDM", "UDR", "PCF", "NSSF", "NRF");

    // Variables pour la corrélation (Mémoire du contrôleur)
    private static int authFailureCount = 0;
    private static long lastAuthFailureTime = 0;

    @PostMapping
    public LogEntry createLog(@RequestBody LogEntry log) {

        // --- MOTEUR DE DÈTECTION IDS (Sprint 2) ---
        boolean intrusionDetected = false;

        // RÈGLE 1 : Détection DoS / Brute Force (CORRÉLATION)
        // On ne déclenche l'alerte que si on dépasse 10 erreurs en 5 secondes
        if (log.getMessage() != null && log.getMessage().contains("Authentication failed")) {
            long currentTime = System.currentTimeMillis();

            // Si plus de 5 secondes se sont écoulées depuis la dernière erreur, on remet le compteur à 0
            if (currentTime - lastAuthFailureTime > 5000) {
                authFailureCount = 0;
            }

            // Mise à jour du temps et incrémentation du compteur
            lastAuthFailureTime = currentTime;
            authFailureCount++;

            System.out.println("⚠️ Tentative échouée (" + authFailureCount + "/10)");

            // SEUIL D'ALERTE : On alerte seulement si on atteint 10
            if (authFailureCount >= 10) {
                log.setAlert(true);
                log.setAlertType("BRUTE FORCE / DoS (Volume élevé)");
                log.setSeverity("CRITICAL");
                intrusionDetected = true;

                // On remet le compteur à 0 pour attendre la prochaine vague d'attaques
                authFailureCount = 0;
            }
        }

        // RÈGLE 2 : Détection Intrusion (NF Inconnue)
        // Si le nom de la NF n'est pas dans la liste blanche OU contient "DARK-WEB"
        else if (log.getNfName() != null && !VALID_NFS.contains(log.getNfName().toUpperCase())) {
            log.setAlert(true);
            log.setAlertType("INTRUSION (Rogue NF)");
            log.setSeverity("HIGH");
            intrusionDetected = true;
        }

        // RÈGLE 3 : Message SBI Malformé
        // Si le message parle d'erreur de syntaxe JSON
        else if (log.getMessage() != null && log.getMessage().contains("JSON syntax error")) {
            log.setAlert(true);
            log.setAlertType("INTEGRITY ERROR (SBI)");
            log.setSeverity("MEDIUM");
            intrusionDetected = true;
        }

        // RÈGLE 4 (Fallback) : Si le Python dit explicitement que c'est une alerte
        else if ("SECURITY_ALERT".equals(log.getEventType()) || "ERROR".equals(log.getLevel())) {
            log.setAlert(true);
            // On garde le type envoyé par Python ou on met une valeur par défaut
            if (log.getAlertType() == null) log.setAlertType("SECURITY INCIDENT");
            if (log.getSeverity() == null) log.setSeverity("HIGH");
            intrusionDetected = true;
        }

        // --- SAUVEGARDE ET ENVOI ---

        // 1. Sauvegarder
        LogEntry savedLog = logRepository.save(log);

        // 2. Envoyer aux logs généraux (Tableau du bas) - Toujours envoyé
        messagingTemplate.convertAndSend("/topic/logs", savedLog);

        // 3. Envoyer aux alertes (Tableau du haut) - UNIQUEMENT SI c'est une attaque confirmée
        if (intrusionDetected) {
            System.out.println("🚨 ALERTE ENVOYÉE : " + log.getAlertType() + " sur " + log.getNfName());
            messagingTemplate.convertAndSend("/topic/alerts", savedLog);
        }

        return savedLog;
    }

    @GetMapping
    public List<LogEntry> getAllLogs() {
        return logRepository.findAll();
    }
}