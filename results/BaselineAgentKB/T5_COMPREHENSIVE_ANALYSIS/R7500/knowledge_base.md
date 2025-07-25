# R7500 (2 alerts)

---

### NVRAM-config-unsafe-strcpy

- **File/Directory Path:** `N/A`
- **Location:** `bin/config:0x8760 (fcn.000086cc)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** An unsafe strcpy call (0xREDACTED_PASSWORD_PLACEHOLDER) was identified in the fcn.000086cc function within bin/config, which directly copies user-controlled input into a stack buffer, potentially leading to buffer overflow. Attackers could exploit this vulnerability by crafting malicious NVRAM configuration values.
- **Code Snippet:**
  ```
  0x0000875c      0d00a0e1       mov r0, sp
  0xREDACTED_PASSWORD_PLACEHOLDER      a0ffffeb       bl sym.imp.strcpy
  ```
- **Keywords:** strcpy, config_set, NVRAM
- **Notes:** Remote triggering requires leveraging additional vulnerabilities (such as CGI input handling).

---
### NVRAM-config-format-string

- **File/Directory Path:** `N/A`
- **Location:** `bin/config:0x89b4 (fcn.000086cc)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A format string vulnerability was discovered in the fcn.000086cc function of bin/config (printf call at 0x000089b4), where an attacker could potentially achieve memory read or write operations by manipulating NVRAM configuration values.
- **Code Snippet:**
  ```
  0x000089b0      00008fe0       add r0, pc, r0
  0x000089b4      0effffeb       bl sym.imp.printf
  ```
- **Keywords:** printf, config_getall, NVRAM
- **Notes:** nvram_get

---
