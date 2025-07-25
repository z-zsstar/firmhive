# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (4 alerts)

---

### SBOM-BusyBox-v1.19.2

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** SBOM analysis for BusyBox binary. Version v1.19.2 (built 2015-11-13). Found CVEs: CVE-2011-2716 (CVSS 6.9), CVE-2013-1813 (CVSS 6.9), CVE-2016-2147 (CVSS 8.3).
- **Code Snippet:**
  ```
  Found in strings output of bin/busybox: 'BusyBox v1.19.2 (2015-11-13 22:58:50 CST)'
  ```
- **Keywords:** BusyBox v1.19.2, 2015-11-13, busybox.lock
- **Notes:** contains multiple known vulnerabilities, including symlink attacks and remote code execution via DHCP

---
### SBOM-zlib-1.1.4

- **File/Directory Path:** `N/A`
- **Location:** `lib/libz.so (HIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** SBOM analysis of the zlib library. Identified that version 1.1.4 contains a known vulnerability CVE-2003-0107 (buffer overflow issue in the gzprintf function).
- **Code Snippet:**
  ```
  Found version strings: '1.1.4', 'deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly', 'inflate 1.1.4 Copyright 1995-2002 Mark Adler'
  ```
- **Keywords:** 1.1.4, deflate 1.1.4 Copyright, inflate 1.1.4 Copyright, CVE-2003-0107, gzprintf
- **Notes:** configuration_load

---
### SBOM-BusyBox-v1.19.2-supplement

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:HIDDENstringsHIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-11-13 22:58:50 CST)
  ```
- **Keywords:** BusyBox, v1.19.2, udhcpc, wget, hush, ash, netstat
- **Notes:** Potential high-risk vulnerabilities that may affect this version:
1. CVE-2016-2148 (DHCP client buffer overflow)
2. CVE-2018-1000517 (wget buffer overflow)
3. CVE-2021-42377 (hush shell command injection)
4. CVE-2022-48174 (ash.c stack overflow)
Recommend checking which vulnerable components are enabled in the target system

---
### SBOM-wget-BusyBox-v1.19.2

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** SBOM analysis for wget (BusyBox applet). Shares BusyBox version v1.19.2. Affected by same CVEs as BusyBox: CVE-2011-2716 (CVSS 6.9), CVE-2013-1813 (CVSS 6.9).
- **Code Snippet:**
  ```
  wget is implemented as a BusyBox applet and shares the BusyBox version
  ```
- **Keywords:** wget BusyBox, BusyBox v1.19.2, busybox.lock
- **Notes:** The wget implementation in this firmware is part of BusyBox and therefore shares the same version and vulnerabilities as the main BusyBox binary

---
