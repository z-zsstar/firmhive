# Archer_C50 (4 alerts)

---

### buffer-overflow-httpd-strcpy

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00408c64-0x00408c78`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** In the http_cgi_main function, unvalidated user input was found to be directly passed to the strcpy function. Attackers can trigger a buffer overflow by crafting specially designed HTTP request parameters. The triggering condition occurs when processing HTTP request parameters, where input length is not validated before being copied into a fixed-size buffer.
- **Code Snippet:**
  ```
  0x00408c64      f882998f       lw t9, -sym.imp.strcpy(gp)
  0x00408c68      dc00a427       addiu a0, sp, 0xdc
  0x00408c6c      9d00a527       addiu a1, sp, 0x9d
  0x00408c70      09f82003       jalr t9
  ```
- **Keywords:** sym.http_cgi_main, sym.imp.strcpy, var_dc, var_9d
- **Notes:** Further verification is required for the target buffer size and the maximum controllable input length.

---
### dos-httpd-reboot

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x004095cc-0x004095e0`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** It was discovered that the system reboot operation (ACT_REBOOT) can be directly triggered via HTTP parameters, which may lead to a denial-of-service attack. The triggering condition involves sending an HTTP request containing specific parameters.
- **Code Snippet:**
  ```
  0x004095cc      98bd8424       addiu a0, a0, -0x4268
  0x004095d0      2482998f       lw t9, -sym.imp.rdp_action(gp)
  0x004095d4      REDACTED_PASSWORD_PLACEHOLDER       nop
  0x004095d8      09f82003       jalr t9
  ```
- **Keywords:** sym.http_cgi_main, sym.imp.rdp_action, str.ACT_REBOOT
- **Notes:** Need to confirm whether there is an access control mechanism protecting this function

---
### buffer-overflow-httpd-sprintf

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER-0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The use of sprintf for string formatting does not impose restrictions on output length, potentially leading to buffer overflow. The trigger condition occurs when processing HTTP responses, where the format string parameters may be controlled by an attacker.
- **Code Snippet:**
  ```
  0xREDACTED_PASSWORD_PLACEHOLDER      7000a427       addiu a0, sp, 0x70
  0xREDACTED_PASSWORD_PLACEHOLDER      fc81998f       lw t9, -sym.imp.sprintf(gp)
  0x0040953c      5ce9a524       addiu a1, a1, -0x16a4
  0xREDACTED_PASSWORD_PLACEHOLDER      09f82003       jalr t9
  ```
- **Keywords:** sym.http_cgi_main, sym.imp.sprintf, var_70, str._error__d
- **Notes:** Need to confirm the size of the var_70 buffer

---
### memory-corruption-httpd-fgets

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00408d20-0x00408f24`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** Multiple unvalidated length checks were identified during HTTP parameter processing, which could lead to memory corruption or information disclosure. The trigger condition involves sending specially crafted parameter values with excessive length.
- **Code Snippet:**
  ```
  0x00408d20      0000058e       lw a1, (s0)
  0x00408d24      e480998f       lw t9, -sym.http_stream_fgets(gp)
  0x00408d28      0011a78f       lw a3, (var_1100h)
  0x00408d2c      0800a48c       lw a0, 8(a1)
  ```
- **Keywords:** sym.http_cgi_main, var_60h, var_50h, sym.http_stream_fgets
- **Notes:** analyze the boundary checks throughout the parameter processing flow

---
