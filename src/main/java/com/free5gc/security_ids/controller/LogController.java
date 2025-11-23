package com.free5gc.security_ids.controller;

import com.free5gc.security_ids.model.LogEntry;
import com.free5gc.security_ids.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController // Dit à Spring : "Ceci est une API REST qui renvoie du JSON"
@RequestMapping("/api/logs") // Tous les endpoints commenceront par cette URL
@RequiredArgsConstructor // Lombok génère le constructeur pour l'injection de dépendances
@CrossOrigin(origins = "*") // TRES IMPORTANT : Autorise Python et React (sur d'autres ports) à parler à l'API
public class LogController {

    private final LogRepository logRepository;

    /**
     * Endpoint pour recevoir un log (Utilisé par le script Python)
     * URL: POST http://localhost:8080/api/logs
     */
    @PostMapping
    public LogEntry createLog(@RequestBody LogEntry log) {
        // 1. On affiche dans la console Java pour voir que ça marche
        System.out.println("📥 Reçu log de " + log.getNfName() + ": " + log.getMessage());

        // 2. On sauvegarde dans MongoDB via le repository
        return logRepository.save(log);
    }

    /**
     * Endpoint pour récupérer tous les logs (Utilisé par le Dashboard React)
     * URL: GET http://localhost:8080/api/logs
     */
    @GetMapping
    public List<LogEntry> getAllLogs() {
        return logRepository.findAll();
    }
}