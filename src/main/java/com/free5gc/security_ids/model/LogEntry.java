package com.free5gc.security_ids.model;

import com.fasterxml.jackson.annotation.JsonProperty;
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

    // CORRECTION ICI : On aligne le nom JSON sur le script Python ("nfName")
    @JsonProperty("nfName")
    private String nfName;

    private String level;
    private String component;
    private String message;

    @JsonProperty("event_type")
    private String eventType;

    private String status;

    // --- Champs enrichis par l'IDS ---
    private boolean isAlert = false;
    private String alertType;
    private String severity;
}