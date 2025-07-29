# RISK ANALYSIS – SVLJmTLSValidatorLUA

A structured threat and mitigation analysis

## 📚 Table of Contents

* [Introduction](#📚-introduction)
* [Protected Assets](#🔐-protected-assets)
* [Identified Risks](#⚠️-identified-risks)
* [Module Assessment (Post-Mitigation)](#🧪-module-assessment-post-mitigation)
* [Recommended Actions](#✅-recommended-actions)
* [Compliance Alignment](#🛡️-compliance-alignment)

---

## 📚 Introduction

The `SVLJmTLSValidatorLUA` protects HTTP-based services hosted in Apache HTTP Server by enforcing strict client authentication using mutual TLS (mTLS).  
It validates X.509 client certificates using configured trust anchors, ensures validity periods, performs issuer and signature algorithm validation, and optionally enforces thumbprint, serial, or EKU constraints.  
This module is designed for Zero Trust environments in critical and public-sector infrastructure.

---

## 🔐 Protected Assets

| Asset                         | Type          | Protection Value |
| ----------------------------- | ------------- | ---------------- |
| Web application backend       | Service       | High             |
| User identity via client cert | Information   | High             |
| CA bundle in PEM format       | Configuration | High             |
| Apache `r` context metadata   | Metadata      | Medium           |
| `mtls-config.properties` file | Configuration | Medium           |

---

## ⚠️ Identified Risks

| Risk ID | Threat                                      | Consequence                           | Likelihood | Risk Level | Comment                                                    |
| ------: | ------------------------------------------- | ------------------------------------- | ---------- | ---------- | ---------------------------------------------------------- |
|      R1 | No actual CRL parsing or revocation logic   | Revoked certificates may be accepted  | Medium     | High       | Fixed in 0.5 via strict CDP HTTP/HTTPS CRL verification    |
|      R2 | Incorrect or tampered CA bundle             | Broken trust chain                    | Low        | High       | PEM parsed blindly – no signature validation               |
|      R3 | Incomplete issuer CN parsing                | False rejection or acceptance         | Low        | Medium     | X.500 parsing aligns with other implementations            |
|      R4 | No OCSP/CRL fallback for offline CA check   | Revoked certs may slip through        | Medium     | Medium     | No OCSP fallback implemented                               |
|      R5 | Lack of structured logging                  | Debugging and traceability is limited | Medium     | Medium     | No integration with syslog/SIEM or audit system            |
|      R6 | Apache `SSLVerifyClient` misconfigured      | No certificate provided to validator  | Medium     | Medium     | Must be enforced in Apache vhost config                    |
|      R7 | Thumbprint/Serial mismatch misconfiguration | Legit clients blocked                 | Medium     | Medium     | Manual entry error could block valid users                 |
|      R8 | Missing EKU check (if required)             | Certs used outside intended scope     | Low        | Medium     | Optional check – not enforced unless configured            |

---

## 🧪 Module Assessment (Post-Mitigation)

| Protection Feature             | Status  | Comment                                                |
| ------------------------------ | ------- | ------------------------------------------------------ |
| HTTPS requirement              | ✅ OK    | Blocks plain HTTP or missing TLS                      |
| Certificate presence           | ✅ OK    | Missing cert triggers immediate redirect              |
| Issuer CN strict match         | ✅ OK    | Parsed with structured X.500 matching                 |
| Issuer thumbprint match        | ✅ OK    | Optional – SHA-1 validated if configured              |
| Certificate NotBefore/NotAfter | ✅ OK    | Enforced with distinct redirect codes                 |
| EKU OID validation             | ✅ OK    | Optional – enforced if present in config              |
| Signature algorithm check      | ✅ OK    | Optional – enforced via config                        |
| Client serial whitelist        | ✅ OK    | Optional – enforced if list present                   |
| Client thumbprint whitelist    | ✅ OK    | Optional – SHA-1 comparison                           |
| CA chain validation            | ✅ OK    | Implemented via `store:verify()`                      |
| CRL revocation check (CDP)     | ✅ OK    | Enforced via HTTP(S) CRL fetch                        |
| Configuration file integrity   | ⚠️ WARN | No schema or init-time verification                    |
| Logging                        | ⚠️ WARN | No syslog or structured log output                     |

---

## ✅ Recommended Actions

| Recommendation                                              | Priority | Justification                                        |
| ----------------------------------------------------------- | -------- | ---------------------------------------------------- |
| Add offline CRL caching (`X509_CRL` parse + file fallback)  | High     | Improve reliability during CDP outages               |
| Validate `mtls-config.properties` on startup                | Medium   | Prevent silent failures or misconfigurations         |
| Add syslog/JSON logging support                             | Medium   | Improve traceability and central monitoring          |
