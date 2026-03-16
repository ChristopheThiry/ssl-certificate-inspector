package org.example.model;

public record KeystoreHealthResponse(
        String status,
        int javaKeystoreCertificatesCount
) {
}

