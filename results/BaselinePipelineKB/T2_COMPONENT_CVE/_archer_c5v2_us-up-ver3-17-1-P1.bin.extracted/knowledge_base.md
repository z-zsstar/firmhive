# _archer_c5v2_us-up-ver3-17-1-P1.bin.extracted (3 alerts)

---

### SBOM-OpenSSL-1.0.0g

- **File/Directory Path:** `N/A`
- **Location:** `lib/libssl.so.1.0.0`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** OpenSSL library version 1.0.0g identified in the firmware. This version is vulnerable to CVE-2014-0224 (CCS Injection) and CVE-2010-4180 (Ciphersuite downgrade).
- **Code Snippet:**
  ```
  Version obtained from filename libssl.so.1.0.0
  ```
- **Keywords:** OpenSSL, libssl, CVE-2014-0224, CVE-2010-4180
- **Notes:** configuration_load

---
### SBOM-vsftpd-2.3.2

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/vsftpd`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** vsFTPd server version 2.3.2 identified in the firmware. This is a known vulnerable version with multiple public vulnerabilities.
- **Code Snippet:**
  ```
  Found version string 'vsftpd: version 2.3.2' in binary
  ```
- **Keywords:** vsftpd, FTP, version 2.3.2
- **Notes:** vsftpd 2.3.2 is an old version with multiple known vulnerabilities. Need to check related CVEs and consider upgrading.

---
### SBOM-LinuxKernel-2.6.36

- **File/Directory Path:** `N/A`
- **Location:** `/etc/rc.d/rc.modules`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The firmware has been identified to use Linux kernel version 2.6.36. This is an older kernel version that may contain multiple vulnerabilities.
- **Code Snippet:**
  ```
  Found version string: 'This board use 2.6.36'
  ```
- **Keywords:** Linux, Kernel, 2.6.36
- **Notes:** configuration_load

---
