package org.example.service;

import org.example.model.CertificateChainResponse;
import org.example.model.CertificateDetails;
import org.example.model.TrustValidationResponse;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

@Service
public class SslCertificateService {

    private static final int DEFAULT_HTTPS_PORT = 443;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
    private final Set<String> javaKeystoreFingerprints = loadJavaKeystoreFingerprints();
    private final X509TrustManager defaultTrustManager;
    private final List<X509Certificate> javaTrustedIssuers;
    private final UntrustedSocketFactory untrustedSocketFactory;
    private final UntrustedSocketFactory trustedSocketFactory;

    public SslCertificateService() {
        this(loadDefaultTrustManagerStatic(), HttpsURLConnection.getDefaultHostnameVerifier(),
                SslCertificateService::openUntrustedSocket, SslCertificateService::openTrustedSocket);
    }

    SslCertificateService(X509TrustManager defaultTrustManager,
                          HostnameVerifier hostnameVerifier,
                          UntrustedSocketFactory untrustedSocketFactory) {
        this(defaultTrustManager, hostnameVerifier, untrustedSocketFactory, untrustedSocketFactory);
    }

    SslCertificateService(X509TrustManager defaultTrustManager,
                          HostnameVerifier hostnameVerifier,
                          UntrustedSocketFactory untrustedSocketFactory,
                          UntrustedSocketFactory trustedSocketFactory) {
        this.defaultTrustManager = defaultTrustManager;
        this.javaTrustedIssuers = loadJavaTrustedIssuers(defaultTrustManager);
        this.untrustedSocketFactory = untrustedSocketFactory;
        this.trustedSocketFactory = trustedSocketFactory;
    }

    public int getJavaKeystoreCertificateCount() {
        return javaKeystoreFingerprints.size();
    }


    public CertificateChainResponse inspectChain(String rawInput) {
        Target target = parseTarget(rawInput);

        // Use an untrusted handshake so chain retrieval is independent from JVM trust store content.
        try (SSLSocket socket = untrustedSocketFactory.create(target.host(), target.port())) {
            socket.startHandshake();

            X509Certificate[] presentedChain = readX509PeerChain(socket.getSession().getPeerCertificates());
            if (presentedChain.length == 0) {
                throw new IllegalStateException("No certificate chain returned by server.");
            }

            List<X509Certificate> resolvedChain = buildResolvedChain(presentedChain);

            List<CertificateDetails> certificates = new ArrayList<>();
            for (X509Certificate certificate : resolvedChain) {
                certificates.add(mapCertificate(certificate, isInJavaKeystore(certificate)));
            }

            if (certificates.isEmpty()) {
                throw new IllegalStateException("No X509 certificate returned by server.");
            }

            return new CertificateChainResponse(rawInput, target.host(), target.port(), certificates);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to fetch SSL certificate: " + exception.getMessage(), exception);
        }
    }

    public TrustValidationResponse validateTrust(String rawInput) {
        Target target = parseTarget(rawInput);
        X509Certificate[] observedChain = fetchObservedPeerChain(target);

        try (SSLSocket socket = trustedSocketFactory.create(target.host(), target.port())) {
            enableHttpsEndpointIdentification(socket, target.host());
            socket.startHandshake();

            X509Certificate[] chain = readX509PeerChain(socket.getSession().getPeerCertificates());
            if (chain.length == 0) {
                return new TrustValidationResponse(rawInput, target.host(), target.port(), false,
                        "No X509 certificate chain was presented by server.");
            }

            defaultTrustManager.checkServerTrusted(chain, chain[0].getPublicKey().getAlgorithm());

            return new TrustValidationResponse(rawInput, target.host(), target.port(), true,
                    "Trusted by default Java TLS validation (certificate chain and hostname).");
        } catch (SSLHandshakeException exception) {
            if (looksLikeHostnameMismatch(exception)) {
                X509Certificate leaf = observedChain.length > 0 ? observedChain[0] : null;
                String details = buildHostnameMismatchMessage(target.host(), leaf);
                return new TrustValidationResponse(rawInput, target.host(), target.port(), false,
                        details + ", tlsReason=" + extractRootCauseMessage(exception));
            }

            return new TrustValidationResponse(rawInput, target.host(), target.port(), false,
                    "TLS trust validation failed: " + extractRootCauseMessage(exception));
        } catch (Exception exception) {
            return new TrustValidationResponse(rawInput, target.host(), target.port(), false,
                    "TLS trust validation failed: " + extractRootCauseMessage(exception));
        }
    }

    private CertificateDetails mapCertificate(X509Certificate certificate, boolean inJavaKeystore) throws Exception {
        return new CertificateDetails(
                certificate.getSubjectX500Principal().getName(),
                certificate.getIssuerX500Principal().getName(),
                certificate.getSerialNumber().toString(16).toUpperCase(),
                DATE_FORMATTER.format(certificate.getNotBefore().toInstant().atOffset(ZoneOffset.UTC)),
                DATE_FORMATTER.format(certificate.getNotAfter().toInstant().atOffset(ZoneOffset.UTC)),
                buildSha256Fingerprint(certificate),
                toPem(certificate),
                readSubjectAlternativeNames(certificate),
                inJavaKeystore
        );
    }

    private boolean isInJavaKeystore(X509Certificate certificate) {
        try {
            return javaKeystoreFingerprints.contains(buildSha256Fingerprint(certificate));
        } catch (Exception exception) {
            return false;
        }
    }

    private Set<String> loadJavaKeystoreFingerprints() {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((java.security.KeyStore) null);

            Set<String> fingerprints = new HashSet<>();
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager x509TrustManager) {
                    for (X509Certificate certificate : x509TrustManager.getAcceptedIssuers()) {
                        fingerprints.add(buildSha256Fingerprint(certificate));
                    }
                }
            }
            return Set.copyOf(fingerprints);
        } catch (Exception exception) {
            return Set.of();
        }
    }

    private List<X509Certificate> loadJavaTrustedIssuers(X509TrustManager trustManager) {
        if (trustManager == null || trustManager.getAcceptedIssuers() == null) {
            return List.of();
        }

        List<X509Certificate> issuers = new ArrayList<>();
        for (X509Certificate issuer : trustManager.getAcceptedIssuers()) {
            if (issuer != null) {
                issuers.add(issuer);
            }
        }
        return List.copyOf(issuers);
    }

    private static X509TrustManager loadDefaultTrustManagerStatic() {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((java.security.KeyStore) null);

            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager x509TrustManager) {
                    return x509TrustManager;
                }
            }
        } catch (Exception ignored) {
            // handled by fallback below
        }
        throw new IllegalStateException("Default X509TrustManager not available.");
    }

    private static SSLSocket openUntrustedSocket(String host, int port) throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, new SecureRandom());

        return (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
    }

    private static SSLSocket openTrustedSocket(String host, int port) throws Exception {
        return (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port);
    }

    private void enableHttpsEndpointIdentification(SSLSocket socket, String host) {
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setServerNames(List.of(new SNIHostName(host)));
        socket.setSSLParameters(parameters);
    }

    private X509Certificate[] fetchObservedPeerChain(Target target) {
        try (SSLSocket socket = untrustedSocketFactory.create(target.host(), target.port())) {
            socket.startHandshake();
            return readX509PeerChain(socket.getSession().getPeerCertificates());
        } catch (Exception exception) {
            return new X509Certificate[0];
        }
    }

    private X509Certificate[] readX509PeerChain(Certificate[] peerCertificates) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Certificate certificate : peerCertificates) {
            if (certificate instanceof X509Certificate x509Certificate) {
                chain.add(x509Certificate);
            }
        }
        return chain.toArray(X509Certificate[]::new);
    }

    private List<X509Certificate> buildResolvedChain(X509Certificate[] presentedChain) {
        List<X509Certificate> orderedPresented = orderPeerChain(presentedChain);
        Map<String, X509Certificate> resolved = new LinkedHashMap<>();
        for (X509Certificate certificate : orderedPresented) {
            resolved.put(fingerprintKey(certificate), certificate);
        }

        Map<String, List<X509Certificate>> issuersBySubject = new LinkedHashMap<>();
        for (X509Certificate issuer : javaTrustedIssuers) {
            issuersBySubject.computeIfAbsent(issuer.getSubjectX500Principal().getName(), key -> new ArrayList<>())
                    .add(issuer);
        }

        X509Certificate current = orderedPresented.get(orderedPresented.size() - 1);
        while (!isSelfSigned(current)) {
            X509Certificate nextIssuer = findIssuer(current, issuersBySubject);
            if (nextIssuer == null) {
                break;
            }

            String key = fingerprintKey(nextIssuer);
            if (resolved.containsKey(key)) {
                break;
            }

            resolved.put(key, nextIssuer);
            current = nextIssuer;
        }

        return new ArrayList<>(resolved.values());
    }

    private List<X509Certificate> orderPeerChain(X509Certificate[] presentedChain) {
        Map<String, X509Certificate> uniqueByFingerprint = new LinkedHashMap<>();
        for (X509Certificate certificate : presentedChain) {
            uniqueByFingerprint.putIfAbsent(fingerprintKey(certificate), certificate);
        }

        List<X509Certificate> unique = new ArrayList<>(uniqueByFingerprint.values());
        if (unique.size() <= 1) {
            return unique;
        }

        Map<String, X509Certificate> bySubject = new LinkedHashMap<>();
        for (X509Certificate certificate : unique) {
            bySubject.put(certificate.getSubjectX500Principal().getName(), certificate);
        }

        Set<String> issuerSubjects = new HashSet<>();
        for (X509Certificate certificate : unique) {
            issuerSubjects.add(certificate.getIssuerX500Principal().getName());
        }

        X509Certificate leaf = unique.stream()
                .filter(certificate -> !issuerSubjects.contains(certificate.getSubjectX500Principal().getName()) || isSelfSigned(certificate))
                .findFirst()
                .orElse(unique.get(0));

        List<X509Certificate> ordered = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        X509Certificate current = leaf;
        while (current != null) {
            String key = fingerprintKey(current);
            if (!visited.add(key)) {
                break;
            }
            ordered.add(current);

            if (isSelfSigned(current)) {
                break;
            }

            X509Certificate issuer = bySubject.get(current.getIssuerX500Principal().getName());
            if (issuer == null || Objects.equals(fingerprintKey(issuer), key)) {
                break;
            }
            current = issuer;
        }

        for (X509Certificate certificate : unique) {
            String key = fingerprintKey(certificate);
            if (!visited.contains(key)) {
                ordered.add(certificate);
            }
        }

        return ordered;
    }

    private X509Certificate findIssuer(X509Certificate certificate, Map<String, List<X509Certificate>> issuersBySubject) {
        List<X509Certificate> candidates = issuersBySubject.get(certificate.getIssuerX500Principal().getName());
        if (candidates == null || candidates.isEmpty()) {
            return null;
        }

        for (X509Certificate candidate : candidates) {
            try {
                certificate.verify(candidate.getPublicKey());
                return candidate;
            } catch (Exception ignored) {
                // Keep searching for another certificate with same subject DN.
            }
        }
        return null;
    }

    private boolean isSelfSigned(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    }

    private String fingerprintKey(X509Certificate certificate) {
        try {
            return buildSha256Fingerprint(certificate);
        } catch (Exception exception) {
            return certificate.getSubjectX500Principal().getName() + "|" + certificate.getSerialNumber();
        }
    }

    private String extractRootCauseMessage(Exception exception) {
        Throwable rootCause = exception;
        while (rootCause.getCause() != null) {
            rootCause = rootCause.getCause();
        }
        return rootCause.getMessage() != null ? rootCause.getMessage() : rootCause.getClass().getSimpleName();
    }

    private Target parseTarget(String rawInput) {
        if (rawInput == null || rawInput.isBlank()) {
            throw new IllegalArgumentException("URL/host must not be empty.");
        }

        String normalized = rawInput.contains("://") ? rawInput : "https://" + rawInput;

        try {
            URI uri = new URI(normalized);
            String host = uri.getHost();
            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Invalid URL/host: " + rawInput);
            }

            int port = uri.getPort() > 0 ? uri.getPort() : DEFAULT_HTTPS_PORT;
            return new Target(host, port);
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Invalid URL syntax: " + rawInput, exception);
        }
    }

    private String buildSha256Fingerprint(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        String hex = HexFormat.of().withUpperCase().formatHex(digest);

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            if (i > 0) {
                result.append(':');
            }
            result.append(hex, i, i + 2);
        }
        return result.toString();
    }

    private String toPem(X509Certificate certificate) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----";
    }

    private String buildHostnameMismatchMessage(String host, X509Certificate leafCertificate) {
        if (leafCertificate == null) {
            return "TLS certificate does not match requested host. requestedHost=" + host
                    + ", leafSubject=unknown, leafSANs=[]";
        }

        String subject;
        try {
            subject = leafCertificate.getSubjectX500Principal() != null
                    ? leafCertificate.getSubjectX500Principal().getName()
                    : "unknown";
        } catch (Exception exception) {
            subject = "unknown";
        }

        List<String> sans;
        try {
            sans = readSubjectAlternativeNames(leafCertificate);
        } catch (Exception exception) {
            sans = List.of();
        }

        return "TLS certificate does not match requested host. requestedHost=" + host
                + ", leafSubject=" + subject
                + ", leafSANs=" + sans;
    }

    private boolean looksLikeHostnameMismatch(Exception exception) {
        String message = extractRootCauseMessage(exception).toLowerCase();
        return message.contains("no name matching")
                || message.contains("subject alternative")
                || message.contains("hostname");
    }

    private List<String> readSubjectAlternativeNames(X509Certificate certificate) {
        try {
            Collection<List<?>> allSans = certificate.getSubjectAlternativeNames();
            if (allSans == null) {
                return List.of();
            }

            List<String> values = new ArrayList<>();
            for (List<?> san : allSans) {
                if (san.size() >= 2 && san.get(0) instanceof Number typeNumber && san.get(1) != null) {
                    values.add(sanTypeLabel(typeNumber.intValue()) + ":" + formatSanValue(san.get(1)));
                }
            }
            return values;
        } catch (Exception exception) {
            return List.of();
        }
    }

    private String formatSanValue(Object sanValue) {
        if (sanValue instanceof byte[] bytes) {
            return HexFormat.of().formatHex(bytes);
        }
        return sanValue.toString();
    }

    private String sanTypeLabel(int sanType) {
        return switch (sanType) {
            case 0 -> "OTHER";
            case 1 -> "EMAIL";
            case 2 -> "DNS";
            case 3 -> "X400";
            case 4 -> "DIR";
            case 5 -> "EDI";
            case 6 -> "URI";
            case 7 -> "IP";
            case 8 -> "RID";
            default -> "TYPE-" + sanType;
        };
    }

    private record Target(String host, int port) {
    }

    @FunctionalInterface
    interface UntrustedSocketFactory {
        SSLSocket create(String host, int port) throws Exception;
    }
}


