# _archer_c5v2_us-up-ver3-17-1-P1.bin.extracted (8 alerts)

---

### MiniDLNA-1.1.0

- **File/Directory Path:** `usr/sbin`
- **Location:** `usr/sbin/minidlnad`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** service
- **Code Snippet:**
  ```
  Found version string in usr/sbin/minidlnad binary (string at offset 0xREDACTED_PASSWORD_PLACEHOLDER)
  ```
- **Keywords:** MiniDLNA, minidlnad
- **Notes:** CVE-2013-2745: An SQL Injection vulnerability exists in MiniDLNA prior to 1.1.0.

---
### pppd-2.4.3

- **File/Directory Path:** `usr/sbin`
- **Location:** `usr/sbin/pppd`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** pppd is a PPP daemon. Version 2.4.3 contains a buffer overflow vulnerability (CVE-2020-8597).
- **Code Snippet:**
  ```
  Found version string in usr/sbin/pppd: 'pppd version 2.4.3'
  ```
- **Keywords:** pppd
- **Notes:** CVE-2020-8597: A buffer overflow vulnerability in the Extensible Authentication Protocol (EAP) packet parser in pppd allows remote attackers to potentially execute arbitrary code via a crafted EAP packet.

---
### vsftpd-2.3.2

- **File/Directory Path:** `usr/sbin`
- **Location:** `usr/sbin/vsftpd`
- **Risk Score:** 9.3
- **Confidence:** 9.5
- **Description:** vsftpd is an FTP server. Version 2.3.2 contains a known backdoor vulnerability (CVE-2011-2523).
- **Code Snippet:**
  ```
  Found version string in usr/sbin/vsftpd: 'vsftpd: version 2.3.2'
  ```
- **Keywords:** vsftpd
- **Notes:** CVE-2011-2523 allows remote command execution when a REDACTED_PASSWORD_PLACEHOLDER is prefixed with ':)', triggering a bind shell on port 6200.

---
### OpenSSL-1.0.0

- **File/Directory Path:** `lib`
- **Location:** `lib/libssl.so.1.0.0, lib/libcrypto.so.1.0.0`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** OpenSSL is a cryptography library. Version 1.0.0 is outdated and may contain vulnerabilities.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libssl, libcrypto
- **Notes:** NVD API request was limited; CVEs need to be checked.

---
### Linux Kernel-2.6.15

- **File/Directory Path:** `lib/modules`
- **Location:** `lib/modules/2.6.15`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** kernel
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** Linux Kernel, 2.6.15
- **Notes:** kernel

---
### BusyBox-1.01

- **File/Directory Path:** `bin`
- **Location:** `bin/busybox, usr/sbin/telnetd`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** utility
- **Code Snippet:**
  ```
  Found version string in usr/sbin/telnetd (symbolic link to busybox): 'BusyBox v1.01 (2016.02.01-08:48+0000)'
  ```
- **Keywords:** BusyBox, v1.01
- **Notes:** CVE-2016-2147 enables remote attackers to execute arbitrary code through a malicious DHCP server.

---
### zlib-1.2.5

- **File/Directory Path:** `lib`
- **Location:** `lib/libz.so.1.2.5`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** zlib is a compression library. Version 1.2.5 is identified in the firmware.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libz
- **Notes:** library

---
### libupnp-3.0.5

- **File/Directory Path:** `lib`
- **Location:** `lib/libupnp.so.3.0.5`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** libupnp is a library for UPnP functionality. Version 3.0.5 is identified in the firmware.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** libupnp
- **Notes:** UPnP implementations are often vulnerable to remote code execution and denial-of-service attacks. CVEs need to be checked for this version.

---
