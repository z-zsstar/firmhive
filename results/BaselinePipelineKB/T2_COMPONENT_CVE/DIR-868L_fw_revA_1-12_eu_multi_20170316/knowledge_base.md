# DIR-868L_fw_revA_1-12_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (3 alerts)

---

### sbom-openssl-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libcrypto.so.1.0.0, lib/libssl.so.1.0.0`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** OpenSSL component version 1.0.0 contains multiple high-risk vulnerabilities:
- CVE-2014-0224 (CVSS 7.4): CCS injection vulnerability may lead to session hijacking
- CVE-2009-1379: Use-after-free vulnerability in DTLS implementation
- CVE-2009-1387: NULL pointer dereference during DTLS handshake
- CVE-2009-4355: zlib compression memory leak
- CVE-2010-0742: CMS implementation vulnerability
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** OpenSSL, 1.0.0, CVE-2014-0224
- **Notes:** contains multiple critical vulnerabilities, requiring urgent upgrade

---
### sbom-openssl-version

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/openssl`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The OpenSSL component version 1.0.2h (released on May 3, 2016) was found to contain embedded version strings in the binary files. This version includes multiple high-risk vulnerabilities:
- CVE-2016-2107: AES-NI CBC MAC padding oracle vulnerability (CVSS 7.5)
- CVE-2016-2105: EVP_EncodeUpdate overflow vulnerability (CVSS 7.5)
- CVE-2016-2106: EBCDIC overread vulnerability (CVSS 5.8)
- CVE-2016-2109: ASN.1 encoder memory corruption vulnerability (CVSS 7.5)
- CVE-2016-2176: SSLv2 cipher suite enforcement vulnerability (CVSS 5.3)
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** openssl, 1.0.2h, CVE-2016-2107, CVE-2016-2105
- **Notes:** Version information was confirmed by analyzing the binary file with the strings command, revealing multiple critical vulnerabilities that require priority handling.

---
### sbom-mt-daapd-component

- **File/Directory Path:** `N/A`
- **Location:** `var/mt-daapd.conf`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** The mt-daapd (Firefly Media Server) component indicates a legacy version (pre-2008) based on its configuration format. It contains a critical vulnerability CVE-2008-1771: integer overflow in the ws_getpostvars function, which may lead to denial of service or arbitrary code execution.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** mt-daapd.conf, Firefly Media Server, ws_getpostvars
- **Notes:** The configuration format indicates a pre-2008 version; the actual version needs to be confirmed by running the service.

---
