package org.example.model;

public record CertificateResponse(
        String input,
        String host,
        int port,
        CertificateDetails certificate
) {
}


