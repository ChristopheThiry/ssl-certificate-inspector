package org.example.api;

import org.example.model.CertificateChainResponse;
import org.example.model.CertificateDetails;
import org.example.model.CertificateResponse;
import org.example.model.TrustValidationResponse;
import org.example.service.SslCertificateService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SslCertificateController.class)
class SslCertificateControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SslCertificateService sslCertificateService;

    @Test
    void shouldReturnCertificateDetails() throws Exception {
        when(sslCertificateService.inspect(anyString())).thenReturn(new CertificateResponse(
                "https://example.com",
                "example.com",
                443,
                new CertificateDetails(
                        "CN=example.com",
                        "CN=Example CA",
                        "A1B2",
                        "2026-01-01T00:00:00Z",
                        "2027-01-01T00:00:00Z",
                        "AA:BB:CC",
                        "-----BEGIN CERTIFICATE-----...",
                        List.of("example.com", "www.example.com"),
                        false
                )
        ));

        mockMvc.perform(get("/api/certificates/inspect").param("url", "https://example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.host").value("example.com"))
                .andExpect(jsonPath("$.port").value(443))
                .andExpect(jsonPath("$.certificate.subject").value("CN=example.com"));
    }

    @Test
    void shouldReturnCertificateChainDetails() throws Exception {
        when(sslCertificateService.inspectChain(anyString())).thenReturn(new CertificateChainResponse(
                "https://example.com",
                "example.com",
                443,
                List.of(
                        new CertificateDetails(
                                "CN=example.com",
                                "CN=Example Intermediate CA",
                                "01",
                                "2026-01-01T00:00:00Z",
                                "2026-06-01T00:00:00Z",
                                "AA:BB:CC",
                                "-----BEGIN CERTIFICATE-----leaf",
                                List.of("example.com"),
                                false
                        ),
                        new CertificateDetails(
                                "CN=Example Intermediate CA",
                                "CN=Example Root CA",
                                "02",
                                "2025-01-01T00:00:00Z",
                                "2030-01-01T00:00:00Z",
                                "DD:EE:FF",
                                "-----BEGIN CERTIFICATE-----intermediate",
                                List.of(),
                                true
                        )
                )
        ));

        mockMvc.perform(get("/api/certificates/inspect-chain").param("url", "https://example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.certificates[0].subject").value("CN=example.com"))
                .andExpect(jsonPath("$.certificates[1].inJavaKeystore").value(true))
                .andExpect(jsonPath("$.certificates.length()").value(2));
    }

    @Test
    void shouldReturnBadRequestWhenServiceFails() throws Exception {
        when(sslCertificateService.inspect(anyString())).thenThrow(new IllegalArgumentException("Invalid URL"));

        mockMvc.perform(get("/api/certificates/inspect").param("url", "not-a-host"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    void shouldReturnHealthWithJavaKeystoreCount() throws Exception {
        when(sslCertificateService.getJavaKeystoreCertificateCount()).thenReturn(152);

        mockMvc.perform(get("/api/certificates/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.javaKeystoreCertificatesCount").value(152));
    }

    @Test
    void shouldReturnTrustValidationResult() throws Exception {
        when(sslCertificateService.validateTrust(anyString())).thenReturn(new TrustValidationResponse(
                "https://example.com",
                "example.com",
                443,
                true,
                "Trusted by default Java trust manager and hostname verifier."
        ));

        mockMvc.perform(get("/api/certificates/validate-trust").param("url", "https://example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.host").value("example.com"))
                .andExpect(jsonPath("$.trusted").value(true));
    }
}


