# R8000-V1.0.4.4_1.1.42 (4 alerts)

---

### env-get-system-0x000384a0

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `httpd:0x000384a0`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The function at 0x000384a0 uses getenv() to retrieve environment variable values and directly incorporates them into system() calls for constructing system commands. If an attacker can manipulate environment variables such as PATH_INFO or LD_LIBRARY_PATH, it may lead to command injection attacks.
- **Code Snippet:**
  ```
  sym.imp.getenv(*0x38e44);
  sym.imp.system(iVar13 + -0x504);
  ```
- **Keywords:** getenv, system, PATH_INFO, LD_LIBRARY_PATH, REQUEST_METHOD, fcn.000384a0
- **Notes:** This is the most critical security issue and needs to be prioritized for fixing.

---
### nvram-set-operation

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `usr/sbin/nvram:0x8904`
- **Risk Score:** 7.5
- **Confidence:** 8.25
- **Description:** The nvram_set function is called at 0x8904 to set the value of an NVRAM variable. The parameters are not adequately validated and could be exploited maliciously.
- **Keywords:** nvram_set
- **Notes:** nvram_set

---
### nvram-get-operation

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `usr/sbin/nvram:0x8878, usr/sbin/nvram:0x8ab4, usr/sbin/nvram:0x8b34`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** The nvram_get function is called at multiple locations (0x8878, 0x8ab4, 0x8b34) to retrieve the values of NVRAM variables. These values are used in string operations (such as strncpy and strcat), which may lead to buffer overflow if not properly validated.
- **Keywords:** nvram_get, strncpy, strcat
- **Notes:** nvram_get

---
### env-set-0x000384a0

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `httpd:0x000384a0`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Multiple instances of using setenv to set environment variables (PATH_INFO, LD_LIBRARY_PATH, etc.), where these values originate from user-controllable input parameters. While not directly causing vulnerabilities, this may affect subsequent process behavior.
- **Code Snippet:**
  ```
  sym.imp.setenv(*0x38e44,iVar13 + -0x304,1);
  sym.imp.setenv(*0x38e50,*0x38e4c,1);
  ```
- **Keywords:** setenv, PATH_INFO, LD_LIBRARY_PATH, REQUEST_METHOD, fcn.000384a0
- **Notes:** It is recommended to verify the sources of these environment variable values and perform sanitization

---
