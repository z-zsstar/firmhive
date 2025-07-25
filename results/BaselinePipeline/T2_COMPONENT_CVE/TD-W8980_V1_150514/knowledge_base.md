# TD-W8980_V1_150514 (11 alerts)

---

### SBOM-OpenSSL-0.9.7f

- **File/Directory Path:** `lib/libssl.so.0.9.7`
- **Location:** `lib/libssl.so.0.9.7: version strings`
- **Risk Score:** 10.0
- **Confidence:** 9.25
- **Description:** Identified OpenSSL version 0.9.7f from binary strings. This is an extremely outdated version (released March 2005) with multiple critical vulnerabilities including remote code execution possibilities.
- **Code Snippet:**
  ```
  OpenSSL 0.9.7f 22 Mar 2005
  SSLv2/3 compatibility part of OpenSSL 0.9.7f 22 Mar 2005
  ```
- **Keywords:** OpenSSL, 0.9.7f, SSLv2, SSLv3
- **Notes:** OpenSSL 0.9.7 series is extremely outdated (2002-2005) and contains multiple critical vulnerabilities. Immediate upgrade is strongly recommended.

---
### VULN-OpenSSL-CVE-2003-0545

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 9.8
- **Confidence:** 8.5
- **Description:** Double free vulnerability allows remote code execution via invalid ASN.1 encoded SSL client certificate (CVSS 9.8).
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** OpenSSL, ASN.1, double free
- **Notes:** vulnerability

---
### VULN-hostapd-CVE-2022-23303

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** SAE implementation side-channel attack vulnerability (CVSS 9.8), affecting hostapd versions prior to 2.10. This vulnerability belongs to the cache access pattern vulnerability category.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** hostapd, SAE, side-channel
- **Notes:** Vulnerability in Cache Access Patterns Affecting SAE Implementation

---
### VULN-hostapd-CVE-2018-17317

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 9.8
- **Confidence:** 6.5
- **Description:** FruityWifi allows remote command execution via hostapd-related parameters containing shell metacharacters (CVSS 9.8). While this specifically affects FruityWifi 2.1, it demonstrates potential attack vectors through hostapd configuration.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** hostapd, FruityWifi, shell metacharacters
- **Notes:** vulnerability

---
### VULN-vsftpd-CVE-2011-2523

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 9.8
- **Confidence:** 6.5
- **Description:** vsftpd 2.3.4 backdoor vulnerability (CVSS 9.8). Historical version backdoor shows need to be vigilant for similar issues in other versions.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** vsftpd, backdoor, 2.3.4
- **Notes:** vulnerability

---
### VULN-vsftpd-CVE-2017-8218

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 9.8
- **Confidence:** 6.0
- **Description:** vulnerability
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** vsftpd, backdoor, TP-Link
- **Notes:** vulnerability

---
### VULN-OpenSSL-CVE-2002-0656

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** vulnerability
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** OpenSSL, buffer overflow, SSL2, SSL3
- **Notes:** Critical vulnerabilities in SSL2/SSL3 implementations

---
### SBOM-hostapd-0.5.9

- **File/Directory Path:** `sbin/hostapd_ath0`
- **Location:** `sbin/hostapd_ath0: version string in binary`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** Identified hostapd version 0.5.9 from binary strings. This is an extremely old version (2010-era) with multiple potential vulnerabilities. Found 3 CVEs that may affect this version through indirect means or similar implementations.
- **Code Snippet:**
  ```
  hostapd v0.5.9
  ```
- **Keywords:** hostapd, v0.5.9, WPS, SAE
- **Notes:** Version 0.5.9 is extremely outdated (from the 2010s). Numerous high-risk vulnerabilities affect newer versions of hostapd. Even if vulnerabilities are not explicitly listed for this version, some may still impact this implementation.

---
### VULN-OpenSSL-CVE-2004-0079

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A null pointer dereference vulnerability exists in the do_change_cipher_spec function, which can be exploited to achieve denial of service attacks (CVSS score 7.5) through carefully crafted SSL/TLS handshakes.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** OpenSSL, do_change_cipher_spec, null dereference
- **Notes:** Affecting SSL/TLS Handshake Processing

---
### VULN-hostapd-CVE-2016-4476

- **File/Directory Path:** `N/A`
- **Location:** `N/A`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** vulnerability
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** hostapd, WPS, DoS
- **Notes:** Affects WPS functionality

---
### SBOM-vsftpd-2.3.2

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `usr/bin/vsftpd:0x00018df0 (rodata section)`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** Identified vsftpd version 2.3.2 from binary strings. While no CVEs specifically target this version, related vulnerabilities suggest potential risks including backdoors and REDACTED_PASSWORD_PLACEHOLDER enumeration.
- **Code Snippet:**
  ```
  vsftpd: version 2.3.2
  ```
- **Keywords:** vsftpd, 2.3.2, vsftpd.conf, anonymous_enable
- **Notes:** No CVEs found specifically for 2.3.2, but related vulnerabilities suggest potential risks. Check configuration for dangerous settings like anonymous access.

---
