package org.example.service;

import org.example.model.TrustValidationResponse;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
        when(socket.getSession()).thenReturn(session);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{certificate});
        when(hostnameVerifier.verify(eq("example.com"), eq(session))).thenReturn(true);

        SslCertificateService service = new SslCertificateService(
                trustManager,
                hostnameVerifier,
                (host, port) -> socket
        );

        TrustValidationResponse response = service.validateTrust("https://example.com");

        assertTrue(response.trusted());
        verify(socket).startHandshake();
        verify(trustManager).checkServerTrusted(any(X509Certificate[].class), eq("RSA"));
        verify(hostnameVerifier).verify(eq("example.com"), eq(session));
    }

    @Test
    void validateTrustShouldReturnFalseWhenHostnameDoesNotMatch() throws Exception {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        HostnameVerifier hostnameVerifier = mock(HostnameVerifier.class);
        SSLSocket socket = mock(SSLSocket.class);
        SSLSession session = mock(SSLSession.class);
        X509Certificate certificate = mock(X509Certificate.class);
        PublicKey publicKey = mock(PublicKey.class);

        when(publicKey.getAlgorithm()).thenReturn("RSA");
        when(certificate.getPublicKey()).thenReturn(publicKey);
        when(socket.getSession()).thenReturn(session);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{certificate});
        when(hostnameVerifier.verify(eq("example.com"), eq(session))).thenReturn(false);

        SslCertificateService service = new SslCertificateService(
                trustManager,
                hostnameVerifier,
                (host, port) -> socket
        );

        TrustValidationResponse response = service.validateTrust("https://example.com");

        assertFalse(response.trusted());
        assertTrue(response.message().contains("does not match"));
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
}

