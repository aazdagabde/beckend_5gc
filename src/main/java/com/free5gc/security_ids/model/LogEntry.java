package com.free5gc.security_ids.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Data // Lombok génère automatiquement les Getters, Setters, toString, etc.
@Document(collection = "logs") // Indique à MongoDB de stocker ça dans la collection "logs"
public class LogEntry {

    @Id
    private String id; // L'ID unique généré par MongoDB (ex: 65a8f...)

    private String timestamp;   // Date et heure de l'événement (format ISO string)
    private String nfName;      // Nom de la Network Function (ex: free5gc-amf)
    private String level;       // INFO, WARN, ERROR
    private String component;   // Module interne (ex: NGAP, NAS)
    private String message;     // Le contenu du log
    private String eventType;   // TRANSACTION, SECURITY_ALERT, ERROR
    private String status;      // SUCCESS, FAILURE

    // Pas besoin d'écrire les getters/setters grâce à @Data !
}