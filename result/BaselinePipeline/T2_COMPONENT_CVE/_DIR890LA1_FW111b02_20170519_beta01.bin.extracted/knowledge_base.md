# _DIR890LA1_FW111b02_REDACTED_PASSWORD_PLACEHOLDER_beta01.bin.extracted (3 alerts)

---

### openssl-crypto

- **File/Directory Path:** `usr/sbin/openssl`
- **Location:** `usr/sbin/openssl: strings output`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** OpenSSL version 1.0.2h identified with multiple critical vulnerabilities including CVE-2016-2177 (CVSS 9.8), CVE-2016-2176 (CVSS 8.2), and others.
- **Code Snippet:**
  ```
  OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL, 1.0.2h
- **Notes:** Critical vulnerability exists. It is recommended to immediately upgrade to OpenSSL 1.0.2u or later.

---
### openssl-library

- **File/Directory Path:** `lib/libssl.so`
- **Location:** `lib/libssl.so: strings output with build timestamp '3 May 2016'`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** OpenSSL version 1.0.2h identified in libssl.so with same vulnerabilities as openssl binary (CVE-2016-2177, CVE-2016-2176, etc.).
- **Code Snippet:**
  ```
  SSLv3 part of OpenSSL 1.0.2h  3 May 2016
  TLSv1 part of OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL, 1.0.2h, SSLv3, TLSv1
- **Notes:** Same critical vulnerabilities as openssl binary. Upgrade to OpenSSL 1.0.2u or later recommended.

---
### minidlna-media-server

- **File/Directory Path:** `usr/bin/minidlna`
- **Location:** `usr/bin/minidlna: Multiple version strings in binary output`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** MiniDLNA version 1.0.24 identified with no known CVEs. Includes dependencies like SQLite (version unknown), FFmpeg libraries (53/51), libexif (12), and others with some potential vulnerabilities.
- **Code Snippet:**
  ```
  Multiple version strings in binary output
  ```
- **Keywords:** MiniDLNA, 1.0.24
- **Notes:** SQLite vulnerabilities may be present but exact version unknown. Recommend obtaining exact versions of all dependencies.

---
