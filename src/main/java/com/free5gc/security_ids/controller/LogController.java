package com.free5gc.security_ids.controller;

import com.free5gc.security_ids.model.LogEntry;
import com.free5gc.security_ids.repository.LogRepository;
import com.free5gc.security_ids.service.SecurityService; // Import du service
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class LogController {

    // On injecte le SecurityService au lieu du Repository directement pour l'ingestion
    private final SecurityService securityService;
    private final LogRepository logRepository; // Gardé pour le GET (affichage)

    /**
     * RECEPTION DES LOGS (Depuis Python)
     */
    @PostMapping
    public LogEntry createLog(@RequestBody LogEntry log) {
        // On passe par le service d'analyse
        return securityService.processLog(log);
    }

    /**
     * CONSULTATION (Pour le Frontend)
     */
    @GetMapping
    public List<LogEntry> getAllLogs() {
        return logRepository.findAll();
    }

    // Petit bonus : Endpoint pour récupérer seulement les alertes
    @GetMapping("/alerts")
    public List<LogEntry> getAlertsOnly() {
        // Note: Tu devras peut-être ajouter "findByIsAlertTrue()" dans ton LogRepository si tu veux optimiser,
        // mais pour l'instant on filtre en Java pour faire simple.
        return logRepository.findAll().stream()
                .filter(LogEntry::isAlert)
                .toList();
    }
}