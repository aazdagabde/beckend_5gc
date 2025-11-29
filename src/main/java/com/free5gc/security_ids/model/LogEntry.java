package com.free5gc.security_ids.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document(collection = "logs")
public class LogEntry {

    @Id
    private String id;

    // --- Données reçues du Script Python ---
    private String timestamp;
    private String nfName;      // ex: "amf", "ausf"
    private String level;       // ex: "INFO", "ERROR"
    private String component;   // ex: "NGAP"
    private String message;     // Le contenu du log
    private String eventType;   // (Optionnel) Type brut
    private String status;      // (Optionnel) Succès/Echec brut

    // --- Champs enrichis par l'IDS (Nouveaux !) ---
    private boolean isAlert = false; // Par défaut, ce n'est pas une alerte
    private String alertType;        // ex: "AUTH_FAILURE", "DOS_ATTACK"
    private String severity;         // ex: "LOW", "MEDIUM", "CRITICAL"
}