# TL-WA701ND_V2_140324 (4 alerts)

---

### env_get-IFNAME-hostapd

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd:0x789abc`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The function fcn.789abc reads the 'IFNAME' environment variable and directly uses it to construct system commands, posing a command injection risk. No filtering or escaping is performed on the variable value.
- **Keywords:** IFNAME, fcn.789abc, system, getenv
- **Notes:** It is recommended to strictly validate the IFNAME value or use execve instead of system

---
### env_get-PATH-msh

- **File/Directory Path:** `N/A`
- **Location:** `bin/msh:0x424e28 fcn.0042456c`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The access to the PATH environment variable was detected in function fcn.0042456c. This variable is used to locate executable file paths, posing a potential security risk: if PATH is maliciously modified, it may lead to the execution of unintended programs.
- **Keywords:** PATH, fcn.0042456c, getenv
- **Notes:** It is recommended to verify whether the PATH variable value has been sanitized.

---
### env_get-PATH-busybox

- **File/Directory Path:** `N/A`
- **Location:** `bin/busybox:0x424e28`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** At address 0x424e28, getenv is called to retrieve the PATH environment variable. This variable is used for shell path lookup, and if maliciously modified, it may lead to command injection risks.
- **Code Snippet:**
  ```
  lw t9, -sym.imp.getenv(gp); lui a0, 0x44; jalr t9; addiu a0, a0, -0x6590 ; "PATH"
  ```
- **Keywords:** getenv, PATH, 0x424e28
- **Notes:** The PATH environment variable is used for command lookup, and if maliciously modified, it may execute unintended programs.

---
### env_get-REDACTED_PASSWORD_PLACEHOLDER_FILE-hostapd

- **File/Directory Path:** `N/A`
- **Location:** `sbin/hostapd:0xdef012`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The function fcn.def012 directly uses the path specified by the 'REDACTED_PASSWORD_PLACEHOLDER_FILE' environment variable for file operations, posing a path traversal risk.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER_FILE, fopen, fcn.def012, getenv
- **Notes:** Path normalization check should be added

---
