package com.free5gc.security_ids.repository;

import com.free5gc.security_ids.model.LogEntry;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LogRepository extends MongoRepository<LogEntry, String> {

    // Méthodes magiques (Spring Data génère le code tout seul)

    // Trouver tous les logs d'une NF spécifique
    List<LogEntry> findByNfName(String nfName);

    // Trouver les logs par statut (ex: FAILURE)
    List<LogEntry> findByStatus(String status);

    // Trouver les logs qui contiennent un mot clé dans le message (pour la recherche)
    List<LogEntry> findByMessageContaining(String keyword);
}