# SVLJmTLSValidatorLUA v1.4.5

**Mutual TLS (mTLS) enforcement script for Apache HTTP Server using mod\_lua**

Maintainer: Svenljunga kommun

---

## Overview

`SVLJmTLSValidatorLUA` is a Lua-based validator that enforces strict mutual TLS (mTLS) in Apache HTTP Server using `mod_lua`.
It verifies client X.509 certificates using local CA bundles, CRL validation, signature and EKU enforcement, and optional restrictions.

**🔗 SVLJmTLSClientValidator**  
SVLJmTLSClientValidator is available for .NET (IIS), Java (Tomcat), and Lua (Apache2), offering identical fail-closed mTLS validation across platforms.  
[`SVLJmTLSClientValidatorModule`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorModule) – .NET `IHttpModule` implementation for IIS  
[`SVLJmTLSClientValidatorFilter`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorFilter) – Java Servlet Filter for Tomcat  
[`SVLJmTLSClientValidatorLUA`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorLUA) – `mod_lua` implementation for Apache2

---

## Features

* 🔐 Strict mTLS enforcement for all incoming HTTPS requests
* ✅ Validation logic:

  * Verifies connection is HTTPS (`SSL_PROTOCOL`)
  * Requires client certificate (`SSL_CLIENT_CERT`)
  * Matches issuer CN against configured name and/or CA bundle
  * Validates certificate chain using CA bundle (PEM format)
  * Validates revocation via CRL Distribution Points (CDP) over HTTP/HTTPS
  * Enforces validity period: NotBefore / NotAfter
  * Optional issuer thumbprint match
  * Optional strict serial whitelist
  * Optional thumbprint whitelist
  * Optional EKU OID validation
  * Optional allowed signature algorithms
  * Optional internal IP bypass
* 📤 Exposes certificate metadata as HTTP headers:

  * `HTTP_SVLJ_SUBJECT`
  * `HTTP_SVLJ_ISSUER`
  * `HTTP_SVLJ_SERIAL`
  * `HTTP_SVLJ_VALIDFROM`
  * `HTTP_SVLJ_VALIDTO`
  * `HTTP_SVLJ_SIGNATUREALG`
  * `HTTP_SVLJ_THUMBPRINT`
* 🚫 Fail-closed model: any validation failure causes redirect

---

## Compliance Alignment

This script supports security controls required by:

- **NIS2 Directive**
- **ISO/IEC 27001 & 27002**
- **GDPR (Art. 32 – Security of processing)**
- **CIS Benchmarks**
- **STIGs (US DoD)**

---

## Requirements

* **Apache HTTP Server 2.4+**
* **mod\_lua** and **mod\_ssl** enabled
* **Lua 5.1+** with `lua-openssl`
* **curl** installed on system
* **PEM-formatted CA bundle**

---

## Dependencies

| Component           | Library/Command         | Notes            |
| ------------------- | ----------------------- | ---------------- |
| Certificate parsing | `lua-openssl`           | Required         |
| CRL download (HTTP) | `curl` via `io.popen()` | Required         |
| CA parsing          | `openssl.x509.store`    | From lua-openssl |
| Config parsing      | `mtls-config.lua`       | Built-in         |

> ✅ No external web libraries or frameworks required

---

## Installation & Configuration

### Directory Structure

```
/etc/apache2/mtls/
├── mtls-validator.lua
├── mtls-config.lua
├── mtls-config.properties
└── ca-bundle.pem
```

### Apache `VirtualHost` Example

```apache
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    SSLCACertificateFile /etc/apache2/mtls/ca-bundle.pem
    SSLVerifyClient require

    LuaHookFixups /etc/apache2/mtls/mtls-validator.lua validate_mtls
</VirtualHost>
```

### mtls-config.properties

```properties
issuer_name = Some CA
issuer_thumbprint = ABCDEF1234567890ABCDEF1234567890ABCDEF12
cert_serial_numbers = 12AB34CD56EF7890,ABCDE12345FEDCBA
allowed_client_thumbprints = 1234567890ABCDEF1234567890ABCDEF12345678,87654321ABCDEF1234567890ABCDEF1234567890
allowed_eku_oids = 1.3.6.1.5.5.7.3.2
allowed_signature_algorithms = sha256WithRSAEncryption,ecdsa-with-SHA256
ca_bundle_path = /etc/apache2/mtls/ca-bundle.pem
error_redirect_url = /error/403c.html
internal_bypass_ips = 127.0.0.1,::1
```

---

## Error Handling

Clients that fail validation are redirected to:

```
/error/403c.html?reason=<reason-code>
```

### Reason Codes

| Code                            | Description                                 |
| ------------------------------- | ------------------------------------------- |
| `insecure-connection`           | Request was made over non-HTTPS             |
| `cert-missing`                  | No client certificate provided              |
| `cert-notyetvalid`              | Certificate validity start date not reached |
| `cert-expired`                  | Certificate has expired                     |
| `issuer-not-trusted`            | Issuer not in trusted CA bundle             |
| `crl-check-failed`              | CRL not valid or certificate is revoked     |
| `serial-not-allowed`            | Serial number not whitelisted               |
| `eku-not-allowed`               | EKU OID missing or not allowed              |
| `sigalg-not-allowed`            | Signature algorithm not in allowed list     |
| `client-thumbprint-not-allowed` | Client thumbprint not allowed               |

---

## Testing

### PowerShell

```powershell
Invoke-WebRequest -Uri "https://your-app" -Certificate (Get-Item Cert:\CurrentUser\My\<THUMBPRINT>)
```

### OpenSSL

```bash
openssl s_client -connect your-app:443 -cert client.crt -key client.key -CAfile ca-bundle.pem
```

### Curl

```bash
curl --cert client.crt --key client.key https://your-app
```
