# _XR500-V2.1.0.4.img.extracted (2 alerts)

---

### openssl-component-1.0.2h

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/openssl:0x0006930e`
- **Risk Score:** 9.8
- **Confidence:** 9.25
- **Description:** The OpenSSL component was detected in the /usr/bin/openssl binary file, with version 1.0.2h (released on May 3, 2016). This version contains multiple critical vulnerabilities:
- CVE-2016-2177 (CVSS 9.8): Pointer arithmetic error leading to heap buffer boundary check issues
- CVE-2016-2176 (CVSS 8.2): Buffer over-read vulnerability in X509_NAME_oneline function
- CVE-2016-2105 (CVSS 7.5): Integer overflow in EVP_EncodeUpdate function
It is recommended to upgrade to OpenSSL 1.0.2u or later.
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, OpenSSLDie, UI_OpenSSL, usr/bin/openssl
- **Notes:** Version evidence location: Offset 0x0006930e in the usr/bin/openssl binary file. 32-bit ARM architecture ELF executable, dynamically linked to uClibc library.

---
### curl-component-7.29.0

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/curl (version string in binary)`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The curl component was found in the /usr/bin/curl binary file, with version 7.29.0 (released in February 2013). This version is severely outdated (current versions are in the 8.x series) and may contain multiple known vulnerabilities. Since the NVD API is unavailable, manual research is required to confirm specific CVEs.
- **Code Snippet:**
  ```
  curl 7.29.0 (embedded string)
  ```
- **Keywords:** curl 7.29.0, usr/bin/curl
- **Notes:** Version evidence source: Embedded strings within the binary file. Manual research required to confirm specific CVE. Current version is severely outdated, recommend upgrading to the 8.x series.

---
