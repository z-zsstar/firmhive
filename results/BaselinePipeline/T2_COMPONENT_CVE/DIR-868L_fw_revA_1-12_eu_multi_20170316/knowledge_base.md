# DIR-868L_fw_revA_1-12_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (3 alerts)

---

### D-Link-DIR-825-Firmware-1.12

- **File/Directory Path:** `etc/config/buildver`
- **Location:** `etc/config/buildver`
- **Risk Score:** 9.8
- **Confidence:** 9.5
- **Description:** firmware version 1.12(g9me)-b04 was identified in the configuration file 'etc/config/buildver'. This version contains multiple critical vulnerabilities including authentication bypass and remote code execution flaws.
- **Code Snippet:**
  ```
  1.12
  ```
- **Keywords:** 1.12, buildver
- **Notes:** firmware

---
### BusyBox-1.14.1

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox (strings output)`
- **Risk Score:** 9.8
- **Confidence:** 9.25
- **Description:** third_party_component
- **Code Snippet:**
  ```
  Found version string 'BusyBox v1.14.1 (2016-09-22 14:40:08 CST)' in binary
  ```
- **Keywords:** BusyBox v1.14.1, udhcpc, OPTION_6RD, telnet, libbb/lineedit.c, hush applet, ash.c
- **Notes:** third_party_component

---
### OpenSSL-1.0.0

- **File/Directory Path:** `lib/libcrypto.so.1.0.0`
- **Location:** `lib/libcrypto.so.1.0.0, lib/libssl.so.1.0.0`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** third_party_component
- **Keywords:** libcrypto.so.1.0.0, libssl.so.1.0.0, libcrypto.so, libssl.so
- **Notes:** third_party_component

---
