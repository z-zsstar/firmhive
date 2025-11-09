# R8500 (6 alerts)

---

### component-openssl-1.0.0g

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so (.rodata section)`
- **Risk Score:** 9.2
- **Confidence:** 8.75
- **Description:** OpenSSL version 1.0.0g (released on January 18, 2012) contains multiple version strings in the .rodata section of the lib/libssl.so file. This version has several critical vulnerabilities.
- **Keywords:** OpenSSL, 1.0.0g, libssl.so, libcrypto.so
- **Notes:** Version 1.0.0g contains multiple high-risk vulnerabilities, particularly CVE-2014-0224 (CCS Injection) with a CVSS score of 7.4. It is recommended to upgrade to the latest stable version of OpenSSL.

---
### component-xagent-3.2.6

- **File/Directory Path:** `N/A`
- **Location:** `opt/xagent/xagent`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** xagent component version 3.2.6, confirmed through string analysis. The uClibc library on which this component depends contains multiple critical vulnerabilities (CVE-2017-9728, CVE-2022-29503, CVE-2021-43523).
- **Keywords:** xagent, 3.2.6, uClibc, libssl.so.1.0.0
- **Notes:** The binary file has been stripped, increasing the analysis difficulty. It is recommended to update the uClibc dependency and recompile.

---
### dependency-openssl-1.0.0

- **File/Directory Path:** `N/A`
- **Location:** `opt/leafp2p/leafp2p`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** OpenSSL 1.0.0 series (end-of-life), identified by library files libssl.so.1.0.0 and libcrypto.so.1.0.0. This version contains multiple known vulnerabilities.
- **Keywords:** OpenSSL, 1.0.0, libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** It is recommended to upgrade to OpenSSL 1.0.2u or a later version. The exact version number needs to be verified.

---
### component-openssl-1.0.0

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** OpenSSL component version 1.0.0 series, identified by the strings 'libssl.so.1.0.0' and 'libcrypto.so.1.0.0'. This version is outdated and contains known vulnerabilities.
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0, CRYPTO_malloc
- **Notes:** configuration_load

---
### component-openssl-1.0.0

- **File/Directory Path:** `N/A`
- **Location:** `opt/xagent/xagent`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** OpenSSL component version 1.0.0, inferred through linked library name. This version may contain unconfirmed vulnerabilities.
- **Keywords:** OpenSSL, 1.0.0, libssl.so.1.0.0, libcrypto.so.1.0.0
- **Notes:** Version information is inferred from the library file name; further confirmation is required for the specific version and patch level.

---
### component-leafp2p-2.1.7

- **File/Directory Path:** `N/A`
- **Location:** `opt/leafp2p/leafp2p`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The leafp2p component version 2.1.7 was confirmed through binary string analysis. This component depends on multiple library files (OpenSSL 1.0.0 series, zlib 1.2.x series, etc.).
- **Keywords:** leafp2p, 2.1.7, libssl.so.1.0.0, libcrypto.so.1.0.0, libz.so.1
- **Notes:** Further verification is required for the exact versions of OpenSSL and zlib. It is recommended to check the relevant CVEs for leafp2p 2.1.7.

---
