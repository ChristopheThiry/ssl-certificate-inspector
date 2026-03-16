package org.example.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.constraints.NotBlank;
import org.example.model.CertificateChainResponse;
import org.example.model.CertificateResponse;
import org.example.model.KeystoreHealthResponse;
import org.example.model.TrustValidationResponse;
import org.example.service.SslCertificateService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/certificates")
@Validated
public class SslCertificateController {

    private final SslCertificateService sslCertificateService;

    public SslCertificateController(SslCertificateService sslCertificateService) {
        this.sslCertificateService = sslCertificateService;
    }

    @GetMapping("/inspect")
    @Operation(summary = "Get SSL certificate for a given site")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Certificate retrieved"),
            @ApiResponse(responseCode = "400", description = "Invalid input or certificate retrieval failure")
    })
    public CertificateResponse inspect(
            @Parameter(example = "https://www.google.com", description = "Domain or URL of the HTTPS site")
            @RequestParam("url") @NotBlank String url) {
        return sslCertificateService.inspect(url);
    }

    @GetMapping("/inspect-chain")
    @Operation(summary = "Get full SSL certificate chain for a given site")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Certificate chain retrieved"),
            @ApiResponse(responseCode = "400", description = "Invalid input or certificate retrieval failure")
    })
    public CertificateChainResponse inspectChain(
            @Parameter(example = "https://www.google.com", description = "Domain or URL of the HTTPS site")
            @RequestParam("url") @NotBlank String url) {
        return sslCertificateService.inspectChain(url);
    }

    @GetMapping("/validate-trust")
    @Operation(summary = "Validate TLS trust with default Java trust manager")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Trust validation result returned"),
            @ApiResponse(responseCode = "400", description = "Invalid input")
    })
    public TrustValidationResponse validateTrust(
            @Parameter(example = "https://www.google.com", description = "Domain or URL of the HTTPS site")
            @RequestParam("url") @NotBlank String url) {
        return sslCertificateService.validateTrust(url);
    }

    @GetMapping("/health")
    @Operation(summary = "Health endpoint with Java keystore certificate count")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Service health returned")
    })
    public KeystoreHealthResponse health() {
        return new KeystoreHealthResponse("UP", sslCertificateService.getJavaKeystoreCertificateCount());
    }
}


