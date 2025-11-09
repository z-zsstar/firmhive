# TL-WR1043ND_V3_150514 (2 alerts)

---

### sbom-uclibc-0.9.30

- **File/Directory Path:** `N/A`
- **Location:** `lib/ld-uClibc-0.9.30.so`
- **Risk Score:** 9.5
- **Confidence:** 8.5
- **Description:** The uClibc C standard library component, version 0.9.30, contains multiple critical vulnerabilities: CVE-2015-8776 (remote code execution, CVSS 9.8) and CVE-2016-2225 (integer overflow DoS, CVSS 7.5).
- **Code Snippet:**
  ```
  lib/ld-uClibc-0.9.30.soHIDDEN
  ```
- **Keywords:** uclibc, 0.9.30, ld-uClibc
- **Notes:** It is recommended to upgrade to version 0.9.33.2 or later.

---
### sbom-libupnp-1.6.x

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/ushareHIDDEN`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** The libupnp library, version 1.6.x (specific version unknown), contains multiple high-risk vulnerabilities: CVE-2016-8863 (heap overflow, CVSS 9.8), CVE-2016-6255 (arbitrary file write, CVSS 7.5), and CVE-2012-5958 (stack overflow).
- **Code Snippet:**
  ```
  HIDDENlibupnp.so.3HIDDEN
  ```
- **Keywords:** libupnp, UpnpInit, REDACTED_SECRET_KEY_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Further confirmation of the exact version of libupnp is required to assess more precise security risks.

---
