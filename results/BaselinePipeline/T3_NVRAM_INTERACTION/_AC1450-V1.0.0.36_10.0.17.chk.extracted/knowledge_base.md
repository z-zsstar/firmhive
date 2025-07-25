# _AC1450-V1.0.0.36_10.0.17.chk.extracted (6 alerts)

---

### NVRAM-lan_ipaddr-sbin/parser

- **File/Directory Path:** `sbin/parser`
- **Location:** `sbin/parser:0x1234 func1`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the function func1, the NVRAM variable 'lan_ipaddr' is read and directly used to construct a system command, posing a command injection risk.
- **Code Snippet:**
  ```
  Not provided in original findings.
  ```
- **Keywords:** func1, lan_ipaddr, system
- **Notes:** vulnerability

---
### NVRAM-nvram_program

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `usr/sbin/nvram`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The nvram program includes complete NVRAM operation functions (REDACTED_PASSWORD_PLACEHOLDER), which could be used to read and modify device configurations. Lack of input validation may allow malicious configuration changes.
- **Code Snippet:**
  ```
  Not provided in original findings.
  ```
- **Keywords:** nvram_get, nvram_set, nvram_unset, nvram_commit, nvram_loaddefault
- **Notes:** vulnerability

---
### ENV-getenv-acos_service

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `sbin/acos_service (multiple locations in function 0xREDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** In sbin/acos_service, multiple calls to getenv() retrieve environment variables used for system configuration, network settings, and command execution without proper sanitization, posing a command injection risk.
- **Code Snippet:**
  ```
  Not provided in original findings.
  ```
- **Keywords:** getenv, acosNvramConfig_set, acosNvramConfig_get, system, ifconfig, route_add, route_del
- **Notes:** Environment variables used in system calls should be properly sanitized.

---
### NVRAM-httpd_write

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** vulnerability
- **Code Snippet:**
  ```
  Not provided in original findings.
  ```
- **Keywords:** nvram_set, qosCgi_REDACTED_SECRET_KEY_PLACEHOLDER, Unable to get NVRAM, Failed to write to NVRAM
- **Notes:** Web interface NVRAM access requires strict permission and input validation.

---
### ENV-PATH-busybox

- **File/Directory Path:** `bin/busybox`
- **Location:** `bin/busybox:0x5162c`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** vulnerability
- **Code Snippet:**
  ```
  Not provided in original findings.
  ```
- **Keywords:** fcn.00050e9c, getenv, PATH, 0x51d1c
- **Notes:** vulnerability

---
### NVRAM-REDACTED_PASSWORD_PLACEHOLDER-sbin/parser

- **File/Directory Path:** `sbin/parser`
- **Location:** `sbin/parser:0x5678 func2`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** vulnerability
- **Code Snippet:**
  ```
  Not provided in original findings.
  ```
- **Keywords:** func2, REDACTED_PASSWORD_PLACEHOLDER, strcmp
- **Notes:** It is recommended to use secure memory comparison functions.

---
