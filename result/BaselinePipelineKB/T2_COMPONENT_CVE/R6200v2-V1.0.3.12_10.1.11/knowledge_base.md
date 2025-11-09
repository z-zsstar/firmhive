# R6200v2-V1.0.3.12_10.1.11 (2 alerts)

---

### SBOM-OpenSSL-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so (version string)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** SBOM component analysis result: OpenSSL version 1.0.0g (18 Jan 2012). Version string found in lib/libssl.so. Multiple high-risk CVEs identified: CVE-2014-0224 (CCS injection, CVSS 7.4), CVE-2010-4180 (cipher suite downgrade), CVE-2010-3864 (heap overflow). Although the exact version 1.0.0g is not explicitly mentioned in CVE descriptions, it belongs to the 1.0.0 series and should be considered as affected. Recommendation: Upgrade to the latest secure version.
- **Code Snippet:**
  ```
  OpenSSL 1.0.0g 18 Jan 2012
  ```
- **Keywords:** OpenSSL, 1.0.0g, libssl, CVE-2014-0224
- **Notes:** configuration_load

---
### SBOM-OpenSSL-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so.1.0.0 -> libssl.so`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** SBOM component analysis result: OpenSSL version is inferred as 1.0.0 (based on symbolic link naming lib/libssl.so.1.0.0). Known CVEs: CVE-2010-4180, CVE-2010-4252, CVE-2011-0014.
- **Code Snippet:**
  ```
  Symbolic link naming suggests version 1.0.0
  ```
- **Keywords:** libssl.so.1.0.0, OpenSSL
- **Notes:** The version is inferred based on symbolic links; further verification is recommended.

---
