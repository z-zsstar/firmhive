# R8500 (3 alerts)

---

### SQLite-3.0

- **File/Directory Path:** `usr/bin/forked-daapd`
- **Location:** `usr/bin/forked-daapd (linked library)`
- **Risk Score:** 9.8
- **Confidence:** 7.5
- **Description:** The linked library 'libsqlite3.so.0' indicates the use of SQLite version 3.0. This version contains multiple security vulnerabilities, including CVE-2021-37832 (SQL injection vulnerability) and CVE-2022-40280 (denial of service vulnerability).
- **Code Snippet:**
  ```
  Linked library: libsqlite3.so.0
  ```
- **Keywords:** libsqlite3.so.0, SQLite, 3.0
- **Notes:** The SQLite vulnerabilities found are implementation-specific and may not affect forked-daapd directly.

---
### avahi-browse-0.6

- **File/Directory Path:** `usr/bin/avahi-browse`
- **Location:** `usr/lib/libavahi-client.so.3 (.rodata section at offset 0x0000f33c)`
- **Risk Score:** 9.1
- **Confidence:** 8.5
- **Description:** The binary file 'usr/bin/avahi-browse' has been identified as Avahi version 0.6. This version contains multiple vulnerabilities, including CVE-2017-6519 (traffic amplification attack), CVE-2021-3468 (infinite loop), and CVE-2006-2289 (buffer overflow).
- **Code Snippet:**
  ```
  Version string: 'avahi 0.6'
  ```
- **Keywords:** avahi 0.6, libavahi-client.so.3, libavahi-common.so.3, libdbus-1.so.3
- **Notes:** This version was identified from the string "avahi 0.6" found in libavahi-client.so.3. This version contains multiple critical vulnerabilities.

---
### pppd-2.4.4

- **File/Directory Path:** `sbin/pppd`
- **Location:** `sbin/pppd`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The binary 'sbin/pppd' is identified as version 2.4.4. This version is affected by CVE-2006-2194 (privilege escalation).
- **Code Snippet:**
  ```
  Version string: '2.4.4'
  ```
- **Keywords:** pppd, 2.4.4
- **Notes:** Recommend updating pppd to version 2.4.7 or later.

---
