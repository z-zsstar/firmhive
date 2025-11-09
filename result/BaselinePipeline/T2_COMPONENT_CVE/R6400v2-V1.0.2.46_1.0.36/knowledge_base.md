# R6400v2-V1.0.2.46_1.0.36 (3 alerts)

---

### libexpat

- **File/Directory Path:** `usr/bin/dbus-daemon`
- **Location:** `Dynamic dependency`
- **Risk Score:** 9.8
- **Confidence:** 8.25
- **Description:** The version of libexpat is unknown (inferred to be prior to 2.4.3 based on CVEs) and contains multiple high-risk vulnerabilities (CVE-2022-22822, CVE-2022-22823, CVE-2022-22824, CVE-2022-23852, CVE-2022-25235).
- **Code Snippet:**
  ```
  Dynamic dependency found in binary: 'libexpat.so.1'
  ```
- **Keywords:** libexpat.so.1
- **Notes:** third_party_component

---
### uClibc

- **File/Directory Path:** `usr/bin/dbus-daemon`
- **Location:** `Dynamic linker reference`
- **Risk Score:** 9.8
- **Confidence:** 7.25
- **Description:** The uClibc version is inferred to be 0.9.33.2 (based on CVEs), containing multiple high-risk vulnerabilities (CVE-2017-9728, CVE-2022-29503, CVE-2021-43523, CVE-2016-6264, CVE-2016-2224).
- **Code Snippet:**
  ```
  Dynamic linker found in binary: '/lib/ld-uClibc.so.0'
  ```
- **Keywords:** /lib/ld-uClibc.so.0
- **Notes:** third_party_component

---
### Avahi

- **File/Directory Path:** `usr/bin/avahi-browse`
- **Location:** `usr/bin/avahi-browse`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Avahi version 0.6.25 contains a denial-of-service vulnerability (CVE-2010-2244).
- **Code Snippet:**
  ```
  Found version string '0.6.25' and function reference 'avahi_client_get_version_string'
  ```
- **Keywords:** 0.6.25, avahi_client_get_version_string
- **Notes:** third_party_component

---
