# Archer_D2_V1_150921 (5 alerts)

---

### OpenSSL-0.9.7f

- **File/Directory Path:** `lib/libssl.so.0.9.7`
- **Location:** `lib/libssl.so.0.9.7: version strings 'SSLv2 part of OpenSSL 0.9.7f 22 Mar 2005' and 'OpenSSL 0.9.7f 22 Mar 2005'`
- **Risk Score:** 9.8
- **Confidence:** 9.5
- **Description:** OpenSSL version 0.9.7f (22 Mar 2005) was found in lib/libssl.so.0.9.7. This version contains multiple critical vulnerabilities, including remote code execution via crafted SSL client certificate (CVE-2003-0545) and null dereference vulnerabilities (CVE-2004-0079).
- **Code Snippet:**
  ```
  SSLv2 part of OpenSSL 0.9.7f 22 Mar 2005
  ```
- **Keywords:** OpenSSL, SSLv2, libssl.so
- **Notes:** vulnerability

---
### Dropbear SSH-2012.55

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER: version string 'SSH-2.0-dropbear_2012.55'`
- **Risk Score:** 9.8
- **Confidence:** 9.25
- **Description:** vulnerability
- **Code Snippet:**
  ```
  SSH-2.0-dropbear_2012.55
  ```
- **Keywords:** Dropbear, SSH-2.0-dropbear_2012.55, dropbearmulti
- **Notes:** vulnerability

---
### libxml-unknown

- **File/Directory Path:** `lib/libxml.so`
- **Location:** `lib/libxml.so: Binary headers`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** libxml.so was found in lib/libxml.so, but its exact version could not be determined. Based on GCC 3.3.2 compilation, it may be libxml2 2.6.x series, which has known vulnerabilities like CVE-2007-6284.
- **Code Snippet:**
  ```
  GCC: (GNU) 3.3.2
  ```
- **Keywords:** libxml, GCC 3.3.2, xml_parseString
- **Notes:** Check other files in the firmware for version information or use binary similarity analysis.

---
### radvd-unknown

- **File/Directory Path:** `usr/sbin/radvd`
- **Location:** `usr/sbin/radvd: strings output`
- **Risk Score:** 7.5
- **Confidence:** 6.0
- **Description:** vulnerability
- **Code Snippet:**
  ```
  Version: %s
  ```
- **Keywords:** radvd, Version: %s
- **Notes:** vulnerability

---
### BusyBox-v1.19.2

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox: Embedded version string 'BusyBox v1.19.2 (2015-07-03 11:30:00 HKT)'`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** configuration
- **Code Snippet:**
  ```
  BusyBox v1.19.2 (2015-07-03 11:30:00 HKT)
  ```
- **Keywords:** busybox, multi-call binary, telnetd
- **Notes:** configuration

---
