# TD-W8980_V1_150514 (6 alerts)

---

### SBOM-OpenSSL-0.9.7f-critical

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so.0.9.7`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** OpenSSL 0.9.7f (released in 2005) contains multiple critical vulnerabilities, including remote code execution risks.
- **Keywords:** OpenSSL, 0.9.7f, crypto

---
### SBOM-libupnp-1.6.6

- **File/Directory Path:** `N/A`
- **Location:** `lib/libupnp.so (version string)`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Confirm that the version of the Portable SDK for UPnP devices (libupnp) is 1.6.6. The evidence source is the string 'Portable SDK for UPnP devices/1.6.6' in the lib/libupnp.so file. This version contains multiple high-risk vulnerabilities.
- **Keywords:** libupnp, UPnP, 1.6.6, Portable SDK
- **Notes:** Version 1.6.6 (released in 2013) contains multiple known critical vulnerabilities, particularly buffer overflow vulnerabilities (CVE-2016-8863, CVE-2012-5958, etc.).

---
### SBOM-KCodes-NetUSB-module

- **File/Directory Path:** `N/A`
- **Location:** `lib/modules/GPL_NetUSB.ko`
- **Risk Score:** 9.1
- **Confidence:** 8.75
- **Description:** The KCodes NetUSB kernel module, identified in lib/modules/GPL_NetUSB.ko with version information Linux 2.6.32.32, contains multiple critical vulnerabilities, including remote code execution and information disclosure flaws.
- **Code Snippet:**
  ```
  vermagic=2.6.32.32 mod_unload MIPS32_R2 32BIT
  ```
- **Keywords:** GPL_NetUSB, KCodes, NetUSB, vermagic=2.6.32.32
- **Notes:** It is recommended to inspect all devices utilizing the KCodes NetUSB module and apply relevant patches as soon as possible.

---
### SBOM-OpenSSL-0.9.7

- **File/Directory Path:** `N/A`
- **Location:** `lib/libcrypto.so.0.9.7, lib/libssl.so.0.9.7`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** By analyzing the files in the lib directory, it was confirmed that the OpenSSL version is 0.9.7. The evidence sources are the filenames 'libcrypto.so.0.9.7' and 'libssl.so.0.9.7'.
- **Keywords:** OpenSSL, 0.9.7, libcrypto.so.0.9.7, libssl.so.0.9.7
- **Notes:** OpenSSL 0.9.7 is a very old version that may contain multiple high-risk vulnerabilities, requiring immediate checking of relevant CVEs.

---
### SBOM-httpd-custom

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Analysis of the httpd binary reveals it to be a custom implementation rather than a known web server. It links multiple proprietary libraries (libcutil.so, libos.so, libcmm.so), which appear to be custom-developed.
- **Keywords:** httpd, custom, libcutil.so, libos.so, libcmm.so
- **Notes:** Further analysis is required regarding the functionality and potential risks of these custom libraries.

---
### SBOM-uClibc-0.9.30.1

- **File/Directory Path:** `N/A`
- **Location:** `lib/ld-uClibc-0.9.30.1.so, lib/libuClibc-0.9.30.1.so`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** By analyzing the files in the lib directory, it was confirmed that the uClibc version is 0.9.30.1. The evidence sources are the filenames 'ld-uClibc-0.9.30.1.so' and 'libuClibc-0.9.30.1.so'.
- **Keywords:** uClibc, 0.9.30.1, ld-uClibc-0.9.30.1.so, libuClibc-0.9.30.1.so
- **Notes:** Query known CVE vulnerabilities for uClibc version 0.9.30.1

---
