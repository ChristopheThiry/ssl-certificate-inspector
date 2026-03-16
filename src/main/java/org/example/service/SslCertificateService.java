package org.example.service;

import org.example.model.CertificateChainResponse;
import org.example.model.CertificateDetails;
import org.example.model.CertificateResponse;
import org.example.model.TrustValidationResponse;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSession;
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
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
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
    private final HostnameVerifier hostnameVerifier;
    private final UntrustedSocketFactory untrustedSocketFactory;

    public SslCertificateService() {
        this(loadDefaultTrustManagerStatic(), HttpsURLConnection.getDefaultHostnameVerifier(),
                SslCertificateService::openUntrustedSocket);
    }

    SslCertificateService(X509TrustManager defaultTrustManager,
                          HostnameVerifier hostnameVerifier,
                          UntrustedSocketFactory untrustedSocketFactory) {
        this.defaultTrustManager = defaultTrustManager;
        this.hostnameVerifier = hostnameVerifier;
        this.untrustedSocketFactory = untrustedSocketFactory;
    }

    public int getJavaKeystoreCertificateCount() {
        return javaKeystoreFingerprints.size();
    }

    public CertificateResponse inspect(String rawInput) {
        Target target = parseTarget(rawInput);

        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(target.host(), target.port())) {
            socket.startHandshake();

            Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain.length == 0 || !(chain[0] instanceof X509Certificate certificate)) {
                throw new IllegalStateException("No X509 certificate returned by server.");
            }

            return new CertificateResponse(rawInput, target.host(), target.port(), mapCertificate(certificate, isInJavaKeystore(certificate)));
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to fetch SSL certificate: " + exception.getMessage(), exception);
        }
    }

    public CertificateChainResponse inspectChain(String rawInput) {
        Target target = parseTarget(rawInput);

        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(target.host(), target.port())) {
            socket.startHandshake();

            Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain.length == 0) {
                throw new IllegalStateException("No certificate chain returned by server.");
            }

            List<CertificateDetails> certificates = new ArrayList<>();
            for (Certificate certificate : chain) {
                if (certificate instanceof X509Certificate x509Certificate) {
                    certificates.add(mapCertificate(x509Certificate, isInJavaKeystore(x509Certificate)));
                }
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

        try (SSLSocket socket = untrustedSocketFactory.create(target.host(), target.port())) {
            socket.startHandshake();

            X509Certificate[] chain = readX509PeerChain(socket.getSession().getPeerCertificates());
            if (chain.length == 0) {
                return new TrustValidationResponse(rawInput, target.host(), target.port(), false,
                        "No X509 certificate chain was presented by server.");
            }

            defaultTrustManager.checkServerTrusted(chain, chain[0].getPublicKey().getAlgorithm());

            SSLSession session = socket.getSession();
            boolean hostMatches = hostnameVerifier.verify(target.host(), session);
            if (!hostMatches) {
                return new TrustValidationResponse(rawInput, target.host(), target.port(), false,
                        "TLS certificate does not match requested host.");
            }

            return new TrustValidationResponse(rawInput, target.host(), target.port(), true,
                    "Trusted by default Java trust manager and hostname verifier.");
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

    private X509Certificate[] readX509PeerChain(Certificate[] peerCertificates) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Certificate certificate : peerCertificates) {
            if (certificate instanceof X509Certificate x509Certificate) {
                chain.add(x509Certificate);
            }
        }
        return chain.toArray(X509Certificate[]::new);
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

    private List<String> readSubjectAlternativeNames(X509Certificate certificate) {
        try {
            Collection<List<?>> allSans = certificate.getSubjectAlternativeNames();
            if (allSans == null) {
                return List.of();
            }

            List<String> values = new ArrayList<>();
            for (List<?> san : allSans) {
                if (san.size() >= 2 && san.get(1) != null) {
                    values.add(san.get(1).toString());
                }
            }
            return values;
        } catch (Exception exception) {
            return List.of();
        }
    }

    private record Target(String host, int port) {
    }

    @FunctionalInterface
    interface UntrustedSocketFactory {
        SSLSocket create(String host, int port) throws Exception;
    }
}


