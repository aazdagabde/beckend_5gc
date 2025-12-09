package com.free5gc.security_ids.controller;

import com.free5gc.security_ids.model.LogEntry;
import com.free5gc.security_ids.repository.LogRepository;
import com.free5gc.security_ids.service.SecurityService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // Autorise le Frontend React
public class LogController {

    private final SecurityService securityService;
    private final LogRepository logRepository;

    @PostMapping
    public LogEntry createLog(@RequestBody LogEntry log) {
        // Délègue toute la logique au service d'analyse
        return securityService.processLog(log);
    }

    @GetMapping
    public List<LogEntry> getAllLogs() {
        return logRepository.findAll();
    }

    @DeleteMapping
    public void deleteAllLogs() {
        logRepository.deleteAll();
    }
}