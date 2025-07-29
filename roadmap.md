# ROADMAP – SVLJmTLSValidatorLUA

This document outlines upcoming features, planned improvements, and architectural goals for future releases of the SVLJ mutual TLS validation script for Apache HTTP Server using `mod_lua`.

---

## ✅ Design Note

All upcoming features will be **optional** and **disabled by default**.
They can be enabled explicitly via `mtls-config.properties` to maintain compatibility and operational control.

The core validator enforces a **fail-closed Zero Trust model**, with mandatory certificate presence, chain validation, and revocation checks.

---

## ✅ Under Consideration (next minor releases)

* [ ] KeyUsage bit enforcement
  *(Block certificates missing `digitalSignature` or with invalid bitmask)*

* [ ] Local fallback cache for CRL
  *(Optional file-based cache if CRL download fails)*

* [ ] Configuration validation at load
  *(Fail-fast if required keys in `mtls-config.properties` are missing or malformed)*

* [ ] JSON-formatted logging to syslog
  *(Emit structured validation results using `os.execute("logger")` or native rsyslog integration)*

* [ ] Structured `HTTP_SVLJ_*` headers
  *(Expose base64-encoded thumbprint, serial, and SANs in consistent format)*

* [ ] Cipher suite validation
  *(Optional rejection of clients using insecure TLS ciphers like 3DES, RC4, or export-grade suites)*

---

## 📆 Tentative Release Targets

| Feature                                      | Target Version |
| -------------------------------------------- | -------------- |
| KeyUsage bit enforcement                     | 1.4.6          |
| JSON-formatted logging                       | 1.4.7          |
| CRL local fallback / caching                 | 1.4.8          |
| Configuration validation                     | 1.4.9          |
| Cipher suite validation                      | 1.5.0          |
| Code & parameter cleanup and standardisation | 1.5.1          |
| OCSP support                                 | x.x            |
