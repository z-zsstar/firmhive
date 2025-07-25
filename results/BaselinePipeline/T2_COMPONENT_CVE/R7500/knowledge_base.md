# R7500 (4 alerts)

---

### dnsmasq-usr-sbin-dnsmasq

- **File/Directory Path:** `usr/sbin/dnsmasq`
- **Location:** `usr/sbin/dnsmasq: version string 'dnsmasq-2.39' found in binary strings`
- **Risk Score:** 9.8
- **Confidence:** 9.0
- **Description:** third_party_component
- **Code Snippet:**
  ```
  dnsmasq-2.39
  ```
- **Keywords:** dnsmasq, IPv6, router advertisement, DHCPv6, DNS, heap overflow
- **Notes:** third_party_component

---
### uhttpd-usr-sbin-uhttpd

- **File/Directory Path:** `usr/sbin/uhttpd`
- **Location:** `usr/sbin/uhttpd: HIDDEN 'Server: uhttpd/1.0.0'`
- **Risk Score:** 9.8
- **Confidence:** 7.0
- **Description:** third_party_component
- **Code Snippet:**
  ```
  Server: uhttpd/1.0.0
  ```
- **Keywords:** uhttpd/1.0.0, strcpy, stack overflow
- **Notes:** Although no CVEs directly targeting uhttpd 1.0.0 were found, multiple high-risk vulnerabilities related to uhttpd have been identified. It is recommended to check the code for similar vulnerability patterns, particularly the use of unsafe functions such as strcpy.

---
### Transmission-usr-bin-transmission-daemon

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER-daemon`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER-daemon: HIDDEN'Transmission 2.76 (13786)'`
- **Risk Score:** 8.8
- **Confidence:** 8.0
- **Description:** The Transmission component version 2.76 (13786) was identified in the binary's embedded strings. This version is affected by CVE-2010-0012, a directory traversal vulnerability that allows remote attackers to overwrite arbitrary files via a crafted .torrent file.
- **Code Snippet:**
  ```
  Transmission 2.76 (13786)
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.c, .torrent file, pathname
- **Notes:** Transmission 2.76 has a directory traversal vulnerability (CVE-2010-0012), it is recommended to upgrade to the fixed version.

---
### hostapd-usr-sbin-hostapd

- **File/Directory Path:** `usr/sbin/hostapd`
- **Location:** `usr/sbin/hostapd: Embedded in binary strings`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** third_party_component
- **Code Snippet:**
  ```
  hostapd v2.2-devel
  ```
- **Keywords:** wpa_cli, hostapd_cli, action scripts
- **Notes:** third_party_component

---
