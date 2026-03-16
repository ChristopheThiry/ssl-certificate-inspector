package org.example.model;

import java.util.List;

public record CertificateDetails(
        String subject,
        String issuer,
        String serialNumberHex,
        String notBefore,
        String notAfter,
        String sha256Fingerprint,
        String pem,
        List<String> subjectAlternativeNames,
        boolean inJavaKeystore
) {
}

