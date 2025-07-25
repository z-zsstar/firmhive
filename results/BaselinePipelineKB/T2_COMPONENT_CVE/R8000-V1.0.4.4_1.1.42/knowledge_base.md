# R8000-V1.0.4.4_1.1.42 (7 alerts)

---

### sbom-openssl-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so.1.0.0`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** OpenSSL version 1.0.2h (released on May 3, 2016), source of evidence: version string in the lib/libssl.so.1.0.0 file. This version contains multiple high-risk vulnerabilities.
- **Keywords:** OpenSSL, 1.0.2h, libssl.so.1.0.0
- **Notes:** upgrade to a supported OpenSSL version immediately

---
### sbom-avahi-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libavahi-client.so`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Third-party component Avahi version 0.6, evidence source: strings 'REDACTED_SECRET_KEY_PLACEHOLDER' and 'avahi 0.6' in the lib/libavahi-client.so file. This version contains multiple high-risk vulnerabilities.
- **Code Snippet:**
  ```
  REDACTED_SECRET_KEY_PLACEHOLDER
  avahi 0.6
  ```
- **Keywords:** avahi 0.6, REDACTED_SECRET_KEY_PLACEHOLDER, libavahi-client.so.3, zeroconf
- **Notes:** It is recommended to upgrade to the latest version to fix known vulnerabilities. Pay special attention to high-risk vulnerabilities such as CVE-2017-6519 (9.1 score) and CVE-2021-3468 (5.5 score).

---
### sbom-avahi-common-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/libavahi-common.so`
- **Risk Score:** 8.5
- **Confidence:** 7.0
- **Description:** Supplementary analysis results for the Avahi component (mDNS/DNS-SD implementation), file path: lib/libavahi-common.so. Although no direct version string is present, the compiler timestamp (Buildroot 2012.02) suggests it may be a version compiled in 2012 (estimated as 0.6.31 or 0.6.32).
- **Keywords:** libavahi-common.so, avahi_malloc, avahi_free, avahi_address_parse, avahi_proto_to_af, avahi_simple_poll_prepare, avahi_threaded_poll_get
- **Notes:** Since the binary file has been stripped (stripped=true), the exact version number cannot be directly obtained. It is recommended to further confirm the version through the following methods:
1. Check other Avahi-related files (such as avahi-daemon) in the same firmware
2. Search for configuration files containing version information
3. Examine the metadata of the build system

---
### sbom-libcurl-version

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi (Dynamic linking reference)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** libcurl version 4, evidence source: www/cgi-bin/genie.cgi dynamically links to libcurl.so.4. This version contains the critical CVE-2024-6197 vulnerability.
- **Keywords:** libcurl, libcurl.so.4, CVE-2024-6197
- **Notes:** The libcurl version needs to be upgraded as soon as possible.

---
### sbom-avahi-daemon-version

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/avahi-daemon`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** Avahi main program version 0.6.25, evidence source: strings 'avahi 0.6.25' and '%s 0.6.25 starting up' in the usr/sbin/avahi-daemon binary file. This version is vulnerable to CVE-2010-2244.
- **Keywords:** avahi-daemon, avahi 0.6.25, mdns
- **Notes:** The previously speculated range of Avahi versions has been confirmed. It is necessary to check the versions of other dependent libraries.

---
### sbom-linux-kernel-version

- **File/Directory Path:** `N/A`
- **Location:** `lib/modules/2.6.36.4brcmarm+/`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Linux kernel version 2.6.36.4brcmarm+, source of evidence: lib/modules/2.6.36.4brcmarm+/ directory path. Indicates a dedicated ARM networking device kernel.
- **Keywords:** Linux Kernel, 2.6.36.4, brcmarm
- **Notes:** Verify kernel module signatures and vulnerability status

---
### sbom-jquery-version

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/jquery.min.js`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** jQuery library version 1.x (estimated), source of evidence: www/cgi-bin/jquery.min.js file (size 77,746 bytes, modified date 2017-11-13). The 1.x series has been discontinued.
- **Keywords:** jQuery, 1.x, javascript library
- **Notes:** Multiple known vulnerabilities exist; an upgrade is recommended.

---
