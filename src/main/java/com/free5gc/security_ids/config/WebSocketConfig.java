package com.free5gc.security_ids.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // Le "topic" sur lequel le frontend va écouter (s'abonner)
        config.enableSimpleBroker("/topic");
        // Préfixe pour les messages envoyés depuis le frontend (si besoin plus tard)
        config.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Point de connexion : http://localhost:8080/ws
        registry.addEndpoint("/ws")
                // IMPORTANT : Autorise Angular/React (port 4200 ou 3000) à se connecter
                .setAllowedOriginPatterns("*")
                .withSockJS(); // Active le fallback si WebSocket n'est pas supporté
    }
}