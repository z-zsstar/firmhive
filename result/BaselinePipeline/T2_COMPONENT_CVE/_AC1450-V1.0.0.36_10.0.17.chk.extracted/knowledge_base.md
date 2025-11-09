# _AC1450-V1.0.0.36_10.0.17.chk.extracted (2 alerts)

---

### OpenSSL-1.0.0

- **File/Directory Path:** `bin/wget`
- **Location:** `bin/wget dynamic dependencies: libssl.so.1.0.0, libcrypto.so.1.0.0`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** OpenSSL library version 1.0.0 contains multiple critical vulnerabilities, including CCS injection vulnerability and heap buffer overflow vulnerability.
- **Code Snippet:**
  ```
  Linked libraries: libssl.so.1.0.0, libcrypto.so.1.0.0
  ```
- **Keywords:** libssl.so.1.0.0, libcrypto.so.1.0.0, OpenSSL 1.0.0
- **Notes:** It is recommended to immediately upgrade OpenSSL to the latest secure version and audit all services using the affected OpenSSL versions.

---
### BusyBox-1.7.2

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox: HIDDEN'BusyBox v1.7.2 (2017-03-22 15:08:43 CST)'`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** BusyBox multi-call binary, version 1.7.2 released in 2017. Need to query CVE vulnerabilities related to this version.
- **Code Snippet:**
  ```
  BusyBox v1.7.2 (2017-03-22 15:08:43 CST)
  ```
- **Keywords:** BusyBox v1.7.2, 2017-03-22 15:08:43 CST, Copyright (C) 1998-2006 Erik Andersen, Rob Landley
- **Notes:** It is necessary to invoke the CVE search tool to query vulnerabilities related to BusyBox 1.7.2. Further analysis of its included applet functions is recommended.

---
