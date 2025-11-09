# TL-MR3020_V1_150921 (2 alerts)

---

### busybox-cves

- **File/Directory Path:** `N/A`
- **Location:** `NVD Database`
- **Risk Score:** 9.0
- **Confidence:** 7.0
- **Description:** Multiple high-risk CVEs found related to BusyBox (version 1.01 detected). While not all directly match this version, they demonstrate common vulnerability patterns in BusyBox implementations.
- **Code Snippet:**
  ```
  Top CVEs:
  1. CVE-2019-5138 (9.9) - Command injection
  2. CVE-2016-2148 (9.8) - DHCP heap overflow
  3. CVE-2016-5791 (9.8) - Unauthenticated TELNET access
  4. CVE-2018-1000517 (9.8) - wget buffer overflow
  5. CVE-2022-48174 (9.8) - Stack overflow in ash
  ```
- **Keywords:** BusyBox, CVE
- **Notes:** vulnerability_reference

---
### busybox-version

- **File/Directory Path:** `N/A`
- **Location:** `./bin/busybox`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The firmware was found to contain BusyBox version 1.01, built on September 21, 2015. This is a critical system component that provides multiple utility tools.
- **Code Snippet:**
  ```
  BusyBox v1.01 (2015.09.21-09:21+0000) Built-in shell (msh)
  ```
- **Keywords:** BusyBox, v1.01
- **Notes:** command_execution

---
