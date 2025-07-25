# DIR-885L_fw_revA_1-13_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (1 alerts)

---

### SBOM-OpenSSL-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so.1.0.0 (HIDDEN)`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** The file lib/libssl.so.1.0.0 was found to contain OpenSSL version 1.0.2h information, which has multiple known critical vulnerabilities. Version string evidence resides in the binary's string table. Identified critical CVEs include: CVE-2016-2177 (score 9.8), CVE-2016-2176 (score 8.2), CVE-2016-2105 (score 7.5), among others. It is recommended to upgrade to an unaffected OpenSSL version as soon as possible.
- **Code Snippet:**
  ```
  SSLv3 part of OpenSSL 1.0.2h  3 May 2016
  ```
- **Keywords:** OpenSSL 1.0.2h, libssl.so.1.0.0, SSLv3 part of OpenSSL
- **Notes:** The identified critical CVEs include: CVE-2016-2177 (9.8 score), CVE-2016-2176 (8.2 score), CVE-2016-2105 (7.5 score), among others. It is recommended to upgrade to an unaffected OpenSSL version as soon as possible.

---
