# Archer_C2_V1_170228 (4 alerts)

---

### SBOM-libupnp-1.6.19

- **File/Directory Path:** `N/A`
- **Location:** `lib/libupnp.so (HIDDEN)`
- **Risk Score:** 9.5
- **Confidence:** 4.5
- **Description:** Portable SDK for UPnP Devices version 1.6.19 was detected in lib/libupnp.so. This version contains multiple critical vulnerabilities, including CVE-2020-13848 (stack overflow) and CVE-2017-1000494 (heap overflow), both with CVSS scores of 9.8.
- **Code Snippet:**
  ```
  'Portable SDK for UPnP devices/1.6.19'
  ```
- **Keywords:** Portable SDK for UPnP Devices, 1.6.19, CVE-2020-13848, CVE-2017-1000494
- **Notes:** SBOM component information - libupnp 1.6.19. It is recommended to upgrade to version 1.14.0 or higher.

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `N/A`
- **Location:** `lib/libuClibc-0.9.33.2.so (HIDDEN)`
- **Risk Score:** 9.5
- **Confidence:** 4.5
- **Description:** Version 0.9.33.2 of uClibc was detected in lib/libuClibc-0.9.33.2.so. This version contains multiple critical vulnerabilities, including CVE-2017-9728 (out-of-bounds read), CVE-2022-29503 (memory corruption), CVE-2017-9729 (stack exhaustion), and CVE-2022-30295 (DNS prediction issue).
- **Keywords:** uClibc, 0.9.33.2, CVE-2017-9728, CVE-2022-29503, CVE-2017-9729, CVE-2022-30295
- **Notes:** SBOM Component Information - uClibc 0.9.33.2. Four newly discovered critical vulnerabilities identified, immediate upgrade recommended.

---
### SBOM-uClibc-0.9.33.2

- **File/Directory Path:** `N/A`
- **Location:** `lib/ld-uClibc-0.9.33.2.so (HIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 4.5
- **Description:** The uClibc version 0.9.33.2 was detected in lib/ld-uClibc-0.9.33.2.so. This version contains multiple critical vulnerabilities, including CVE-2016-2225 (DoS vulnerability) and CVE-2015-8776 (integer overflow vulnerability).
- **Keywords:** uClibc, 0.9.33.2, CVE-2016-2225, CVE-2015-8776
- **Notes:** SBOM component information - uClibc 0.9.33.2. It is recommended to upgrade to version 0.9.33.3 or higher.

---
### SBOM-GCC-4.6.3

- **File/Directory Path:** `N/A`
- **Location:** `lib/libupnp.so (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 4.5
- **Description:** GCC compiler version 4.6.3 was detected in lib/libupnp.so. This version is affected by CVE-2018-12886 (Stack Protection Bypass Vulnerability) with a CVSS score of 7.5.
- **Code Snippet:**
  ```
  'GCC: (Buildroot 2012.11.1) 4.6.3'
  ```
- **Keywords:** GCC, 4.6.3, CVE-2018-12886, Buildroot 2012.11.1
- **Notes:** SBOM component information - GCC 4.6.3. It is recommended to use a more modern compiler version.

---
