# R7000 (1 alerts)

---

### sbom-openssl-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so.1.0.0`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The OpenSSL component version 1.0.2h was detected, containing three known critical vulnerabilities (CVE-2016-2107, CVE-2016-2105, CVE-2016-2106). This version is susceptible to padding oracle attacks and buffer overflow vulnerabilities.
- **Keywords:** OpenSSL, SSLv3_method, ssl3_new, TLSv1_method, libssl.so.1.0.0
- **Notes:** Version information from string: 'OpenSSL 1.0.2h  3 May 2016'. Related vulnerabilities:
- CVE-2016-2107 (CVSS 5.9): Padding oracle in AES-NI CBC MAC check
- CVE-2016-2105 (CVSS 7.5): EVP_EncodeUpdate overflow
- CVE-2016-2106 (CVSS 7.5): EVP_EncryptUpdate overflow

---
