package org.example.model;

import java.util.List;

public record CertificateChainResponse(
        String input,
        String host,
        int port,
        List<CertificateDetails> certificates
) {
}

