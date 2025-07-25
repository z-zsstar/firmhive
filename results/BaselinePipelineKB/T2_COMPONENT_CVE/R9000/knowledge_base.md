# R9000 (17 alerts)

---

### SBOM-OpenSSL-0.9.8p

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libssl.so.0.9.8`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** Analysis results of OpenSSL component. Version 0.9.8p (16 Nov 2010) contains multiple known critical vulnerabilities, including certificate forgery and weak REDACTED_PASSWORD_PLACEHOLDER generation issues. The version string is embedded within the binary file.
- **Code Snippet:**
  ```
  Embedded version string found in binary
  ```
- **Keywords:** OpenSSL, 0.9.8p, libssl, CVE-2005-2946, CVE-2008-0166, CVE-2005-2969, CVE-2006-4339, CVE-2006-2937
- **Notes:** This version is no longer maintained and contains multiple known vulnerabilities. It is recommended to upgrade immediately.

---
### VULN-CVE-2010-0012

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Risk Score:** 8.8
- **Confidence:** 7.0
- **Description:** Directory traversal vulnerability in REDACTED_PASSWORD_PLACEHOLDER.c in Transmission 1.22, 1.34, 1.75, and 1.76 allows remote attackers to overwrite arbitrary files via a .. (dot dot) in a pathname within a .torrent file.
- **Keywords:** Transmission, 2.76, CVE-2010-0012, libtransmission, metainfo.c, .torrent
- **Notes:** Although version 2.76 does not explicitly list it, the vulnerability may still exist, and further verification is recommended.

---
### SBOM-OpenSSL-0.9.8p

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** OpenSSL component analysis results. Version 0.9.8p (16 Nov 2010) contains multiple known critical vulnerabilities. Version string evidence is located at binary file address 0xREDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  Version string found at address 0xREDACTED_PASSWORD_PLACEHOLDER in binary
  ```
- **Keywords:** OpenSSL, 0.9.8p, CVE-2005-2946, CVE-2008-0166, CVE-2005-2969, CVE-2006-4339, CVE-2006-2937, CVE-2006-2940, CVE-2006-3738, CVE-2006-4343, CVE-2007-3108, CVE-2007-5135
- **Notes:** configuration_load

---
### VULN-CVE-2007-3108

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** configuration_load
- **Keywords:** OpenSSL, 0.9.8p, CVE-2007-3108, RSA

---
### VULN-CVE-2006-3738

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Buffer overflow vulnerability in the SSL_get_shared_ciphers function
- **Keywords:** OpenSSL, 0.9.8p, CVE-2006-3738, buffer

---
### SBOM-Transmission-2.76

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER-daemon:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** Analysis results of the Transmission component. Version 2.76 (13786) may contain a directory traversal vulnerability (CVE-2010-0012). Version string evidence is located at binary file address 0xREDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  Transmission 2.76 (13786)  http://www.transmissionbt.com/
  ```
- **Keywords:** Transmission, 2.76, CVE-2010-0012, libtransmission, metainfo.c, .torrent
- **Notes:** It is recommended to check for the existence of the metainfo.c file to confirm whether the vulnerability exists. Most other CVEs are related to different software or protocols and do not directly affect this component.

---
### SBOM-OpenSSL-0.9.8

- **File/Directory Path:** `N/A`
- **Location:** `etc/easy-rsa/openssl-0.9.8.cnf`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** OpenSSL component preliminary identification result. Version 0.9.8 confirmed via configuration file name.
- **Code Snippet:**
  ```
  HIDDEN
  ```
- **Keywords:** OpenSSL, 0.9.8, openssl.cnf
- **Notes:** OpenSSL 0.9.8 is a very old version that may contain numerous known vulnerabilities and should be prioritized for upgrade.

---
### VULN-CVE-2005-2946

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libssl.so.0.9.8`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** cryptographic_weakness
- **Keywords:** OpenSSL, 0.9.8p, CVE-2005-2946, MD5, certificate

---
### VULN-CVE-2008-0166

- **File/Directory Path:** `N/A`
- **Location:** `usr/lib/libssl.so.0.9.8`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** cryptographic_weakness
- **Keywords:** OpenSSL, 0.9.8p, CVE-2008-0166, random, key_generation

---
### VULN-CVE-2005-2946

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The default configuration uses MD5 for creating message digests instead of a more REDACTED_SECRET_KEY_PLACEHOLDER strong algorithm, making it easier to forge certificates
- **Keywords:** OpenSSL, 0.9.8p, CVE-2005-2946, MD5

---
### VULN-CVE-2008-0166

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Debian-based systems use a predictable random number generator, making brute force attacks easier
- **Keywords:** OpenSSL, 0.9.8p, CVE-2008-0166, random

---
### VULN-CVE-2007-5135

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** off-by-one error in the SSL_get_shared_ciphers function
- **Keywords:** OpenSSL, 0.9.8p, CVE-2007-5135, buffer

---
### VULN-CVE-2005-2969

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** SSL/TLS server disables verification steps, allowing protocol version rollback attacks
- **Keywords:** OpenSSL, 0.9.8p, CVE-2005-2969, SSL, TLS

---
### VULN-CVE-2006-4339

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** RSA REDACTED_PASSWORD_PLACEHOLDER with exponent 3 vulnerability allowing signature forgery
- **Keywords:** OpenSSL, 0.9.8p, CVE-2006-4339, RSA

---
### VULN-CVE-2006-2937

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Denial of service via malformed ASN.1 structures
- **Keywords:** OpenSSL, 0.9.8p, CVE-2006-2937, ASN.1

---
### VULN-CVE-2006-2940

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Consuming CPU by parasitic public keys
- **Keywords:** OpenSSL, 0.9.8p, CVE-2006-2940, CPU

---
### VULN-CVE-2006-4343

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Null pointer dereference in SSLv2 client leads to denial of service
- **Keywords:** OpenSSL, 0.9.8p, CVE-2006-4343, SSLv2

---
