# FH1201 (3 alerts)

---

### Linux-Kernel-2.6.22

- **File/Directory Path:** `/lib/modules/2.6.22`
- **Location:** `/lib/modules/2.6.22`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** Linux kernel version 2.6.22 was identified through directory structure. This extremely outdated version has multiple known vulnerabilities including privilege escalation and denial of service.
- **Keywords:** kernel-2.6.22, udp_sendmsg, register_filesystem
- **Notes:** vulnerability

---
### BusyBox-1.13.0

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox (string analysis)`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** BusyBox version 1.13.0 was identified with multiple high-severity vulnerabilities. Version evidence was found in the binary strings. This version is vulnerable to buffer overflows and arbitrary code execution via crafted inputs.
- **Code Snippet:**
  ```
  Found version string: 'BusyBox v1.13.0 (2013-08-29 17:44:59 CST)'
  ```
- **Keywords:** BusyBox v1.13.0, udhcp client, libbb/lineedit.c, ncompress
- **Notes:** vulnerability

---
### miniupnpd-1.4

- **File/Directory Path:** `bin/miniupnpd`
- **Location:** `bin/miniupnpd (string analysis)`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** miniupnpd version 1.4 was confirmed with CVE-2013-0229 vulnerability allowing SSDP-based denial of service through buffer over-read.
- **Code Snippet:**
  ```
  Found version strings: 'MiniUPnPd/1.4', 'REDACTED_PASSWORD_PLACEHOLDER'
  ```
- **Keywords:** MiniUPnPd/1.4, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_SECRET_KEY_PLACEHOLDER, minissdp.c
- **Notes:** vulnerability

---
