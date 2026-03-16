package org.example.model;

public record TrustValidationResponse(
        String input,
        String host,
        int port,
        boolean trusted,
        String message
) {
}

