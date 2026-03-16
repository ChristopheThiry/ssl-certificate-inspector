package org.example.service;

import org.example.model.TrustValidationResponse;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;

class SslCertificateServiceTest {


    @Test
    void validateTrustShouldReturnTrustedWhenChainAndHostnameAreValid() throws Exception {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        HostnameVerifier hostnameVerifier = mock(HostnameVerifier.class);
        SSLSocket socket = mock(SSLSocket.class);
        SSLSession session = mock(SSLSession.class);
        X509Certificate certificate = mock(X509Certificate.class);
        PublicKey publicKey = mock(PublicKey.class);

        when(publicKey.getAlgorithm()).thenReturn("RSA");
        when(certificate.getPublicKey()).thenReturn(publicKey);
        when(socket.getSSLParameters()).thenReturn(new SSLParameters());
        when(socket.getSession()).thenReturn(session);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{certificate});

        SslCertificateService service = new SslCertificateService(
                trustManager,
                hostnameVerifier,
                (host, port) -> socket
        );

        TrustValidationResponse response = service.validateTrust("https://example.com");

        assertTrue(response.trusted());
        verify(socket, times(2)).startHandshake();
        verify(trustManager).checkServerTrusted(any(X509Certificate[].class), eq("RSA"));
        assertTrue(response.message().contains("default Java TLS validation"));
    }

    @Test
    void validateTrustShouldReturnFalseWhenHostnameDoesNotMatch() throws Exception {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        HostnameVerifier hostnameVerifier = mock(HostnameVerifier.class);
        SSLSocket observedSocket = mock(SSLSocket.class);
        SSLSession observedSession = mock(SSLSession.class);
        X509Certificate certificate = mockCertificate("CN=example.com", "CN=issuer.example", "11", "leaf-hostname");
        when(certificate.getSubjectAlternativeNames()).thenReturn(List.of(List.of(2, "www.example.com")));

        SSLSocket trustedSocket = mock(SSLSocket.class);
        when(observedSocket.getSession()).thenReturn(observedSession);
        when(observedSession.getPeerCertificates()).thenReturn(new Certificate[]{certificate});
        when(trustedSocket.getSSLParameters()).thenReturn(new SSLParameters());
        doThrow(new SSLHandshakeException("No subject alternative DNS name matching example.com found"))
                .when(trustedSocket)
                .startHandshake();

        SslCertificateService service = new SslCertificateService(
                trustManager,
                hostnameVerifier,
                (host, port) -> observedSocket,
                (host, port) -> trustedSocket
        );

        TrustValidationResponse response = service.validateTrust("https://example.com");

        assertFalse(response.trusted());
        assertTrue(response.message().contains("does not match"));
        assertTrue(response.message().contains("requestedHost=example.com"));
        assertTrue(response.message().contains("leafSANs=[DNS:www.example.com]"));
        assertTrue(response.message().contains("tlsReason=No subject alternative DNS name matching example.com found"));
    }

    @Test
    void validateTrustShouldReturnFalseWhenTrustManagerRejectsChain() throws Exception {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        HostnameVerifier hostnameVerifier = mock(HostnameVerifier.class);
        SSLSocket socket = mock(SSLSocket.class);
        SSLSession session = mock(SSLSession.class);
        X509Certificate certificate = mock(X509Certificate.class);
        PublicKey publicKey = mock(PublicKey.class);

        when(publicKey.getAlgorithm()).thenReturn("RSA");
        when(certificate.getPublicKey()).thenReturn(publicKey);
        when(socket.getSSLParameters()).thenReturn(new SSLParameters());
        when(socket.getSession()).thenReturn(session);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{certificate});
        doThrow(new CertificateException("PKIX path building failed"))
                .when(trustManager)
                .checkServerTrusted(any(X509Certificate[].class), anyString());

        SslCertificateService service = new SslCertificateService(
                trustManager,
                hostnameVerifier,
                (host, port) -> socket
        );

        TrustValidationResponse response = service.validateTrust("https://example.com");

        assertFalse(response.trusted());
        assertTrue(response.message().contains("PKIX path building failed"));
    }

    @Test
    void validateTrustShouldReturnFalseWhenNoX509ChainIsPresented() throws Exception {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        HostnameVerifier hostnameVerifier = mock(HostnameVerifier.class);
        SSLSocket socket = mock(SSLSocket.class);
        SSLSession session = mock(SSLSession.class);

        when(socket.getSession()).thenReturn(session);
        when(socket.getSSLParameters()).thenReturn(new SSLParameters());
        when(session.getPeerCertificates()).thenReturn(new Certificate[0]);

        SslCertificateService service = new SslCertificateService(
                trustManager,
                hostnameVerifier,
                (host, port) -> socket
        );

        TrustValidationResponse response = service.validateTrust("https://example.com");

        assertFalse(response.trusted());
        assertTrue(response.message().contains("No X509 certificate chain"));
    }

    @Test
    void inspectChainShouldReturnLeafFirstAndAppendJavaIssuerWhenMissing() throws Exception {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        HostnameVerifier hostnameVerifier = mock(HostnameVerifier.class);
        SSLSocket socket = mock(SSLSocket.class);
        SSLSession session = mock(SSLSession.class);

        X509Certificate leaf = mockCertificate("CN=leaf.example", "CN=intermediate.example", "01", "leaf");
        X509Certificate intermediate = mockCertificate("CN=intermediate.example", "CN=root.example", "02", "intermediate");
        X509Certificate root = mockCertificate("CN=root.example", "CN=root.example", "03", "root");

        PublicKey rootKey = mock(PublicKey.class);
        when(root.getPublicKey()).thenReturn(rootKey);
        when(root.getSubjectAlternativeNames()).thenReturn(null);
        when(intermediate.getSubjectAlternativeNames()).thenReturn(null);
        when(leaf.getSubjectAlternativeNames()).thenReturn(null);
        when(intermediate.getPublicKey()).thenReturn(mock(PublicKey.class));
        when(leaf.getPublicKey()).thenReturn(mock(PublicKey.class));

        when(trustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{root});
        when(socket.getSession()).thenReturn(session);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{intermediate, leaf});

        SslCertificateService service = new SslCertificateService(
                trustManager,
                hostnameVerifier,
                (host, port) -> socket
        );

        var response = service.inspectChain("https://example.com");

        assertEquals(3, response.certificates().size());
        assertEquals("CN=leaf.example", response.certificates().get(0).subject());
        assertEquals("CN=intermediate.example", response.certificates().get(1).subject());
        assertEquals("CN=root.example", response.certificates().get(2).subject());
        verify(intermediate).verify(eq(rootKey));
    }

    @Test
    void inspectChainShouldIncludeSanTypePrefixes() throws Exception {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        HostnameVerifier hostnameVerifier = mock(HostnameVerifier.class);
        SSLSocket socket = mock(SSLSocket.class);
        SSLSession session = mock(SSLSession.class);

        X509Certificate leaf = mockCertificate("CN=leaf.example", "CN=leaf.example", "10", "leaf-san");
        when(leaf.getSubjectAlternativeNames()).thenReturn(List.of(
                List.of(2, "www.example.com"),
                List.of(6, "spiffe://workload/example")
        ));

        when(trustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[0]);
        when(socket.getSession()).thenReturn(session);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{leaf});

        SslCertificateService service = new SslCertificateService(
                trustManager,
                hostnameVerifier,
                (host, port) -> socket
        );

        var response = service.inspectChain("https://example.com");

        assertEquals(List.of("DNS:www.example.com", "URI:spiffe://workload/example"),
                response.certificates().get(0).subjectAlternativeNames());
    }

    private X509Certificate mockCertificate(String subject, String issuer, String serial, String encodedSeed) throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(subject));
        when(certificate.getIssuerX500Principal()).thenReturn(new X500Principal(issuer));
        when(certificate.getSerialNumber()).thenReturn(new java.math.BigInteger(serial, 16));
        when(certificate.getEncoded()).thenReturn(encodedSeed.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        when(certificate.getNotBefore()).thenReturn(new Date(0));
        when(certificate.getNotAfter()).thenReturn(new Date(86_400_000L));

        // Most tests do not care about signature checks; use lenient stubbing to avoid strict interactions.
        lenient().doNothing().when(certificate).verify(argThat(key -> true));
        return certificate;
    }
}

