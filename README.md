# SSL Certificate Inspector (Spring Boot)

API Spring Boot qui recupere le certificat SSL presente par un site HTTPS.

## Prerequis

- Java 21
- Maven 3.9+

## Lancer l'application

```bash
mvn spring-boot:run
```

## Swagger UI

Une fois demarre, ouvre:

- http://localhost:8080/swagger-ui/index.html

Endpoint principal:

- `GET /api/certificates/inspect-chain?url=https://www.google.com`
- `GET /api/certificates/validate-trust?url=https://www.google.com`
- `GET /api/certificates/health`

Le parametre `url` accepte:

- une URL complete (`https://example.com`)
- ou juste un host (`example.com`)


## Exemple de reponse (chaine complete)

```json
{
  "input": "https://www.google.com",
  "host": "www.google.com",
  "port": 443,
  "certificates": [
    {
      "subject": "CN=www.google.com",
      "issuer": "CN=WR2, O=Google Trust Services, C=US",
      "serialNumberHex": "...",
      "notBefore": "2026-01-01T00:00:00Z",
      "notAfter": "2026-03-31T23:59:59Z",
      "sha256Fingerprint": "AA:BB:CC:...",
      "pem": "-----BEGIN CERTIFICATE-----...",
      "subjectAlternativeNames": ["www.google.com", "google.com"],
      "inJavaKeystore": false
    }
  ]
}
```

## Tests

```bash
mvn test
```

## IntelliJ: utiliser le Maven local installe

Si IntelliJ n'utilise pas encore ton Maven local:

1. Ouvre `File > Settings > Build, Execution, Deployment > Build Tools > Maven`
2. Dans `Maven home path`, selectionne:
   `C:\Users\thiry\AppData\Local\Programs\apache-maven-3.9.14`
3. Applique puis relance l'import Maven du projet.


