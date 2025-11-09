# Archer_C2_V1_170228 (3 alerts)

---

### vsftpd-2.3.2

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `usr/bin/vsftpd:0x00025a50`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** vsftpd version 2.3.2 was identified in the binary. This version is known to contain critical vulnerabilities including a backdoor vulnerability (CVE-2011-2523).
- **Code Snippet:**
  ```
  vsftpd: version 2.3.2
  ```
- **Keywords:** vsftpd, version_2.3.2, CVE-2011-2523
- **Notes:** third_party_component

---
### uclibc-0.9.33.2

- **File/Directory Path:** `lib/ld-uClibc-0.9.33.2.so`
- **Location:** `lib/ld-uClibc-0.9.33.2.so`
- **Risk Score:** 9.8
- **Confidence:** 8.75
- **Description:** third_party_component
- **Code Snippet:**
  ```
  N/A (version from filename)
  ```
- **Keywords:** get_subexp, regexec.c, misc/regex, libpthread, linuxthreads, DNS, transaction IDs
- **Notes:** third_party_component

---
### busybox-1.19.2

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x0043e071`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** third_party_component
- **Code Snippet:**
  ```
  'out of memoryBusyBox v1.19.2 (2016-0'
  ```
- **Keywords:** BusyBox v1.19.2, 2016-09-13 10:03:21 HKT
- **Notes:** No CVEs were found for BusyBox v1.19.2 in the NVD database. Consider checking other vulnerability databases or sources for potential issues.

---
