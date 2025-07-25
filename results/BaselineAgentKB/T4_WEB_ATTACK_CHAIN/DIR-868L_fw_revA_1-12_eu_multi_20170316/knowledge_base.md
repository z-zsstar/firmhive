# DIR-868L_fw_revA_1-12_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (3 alerts)

---

### CGI-System-Call-1

- **File/Directory Path:** `N/A`
- **Location:** `htdocs/cgibin:0x0000ec90 (fcn.0000e4f0)`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** In the fcn.0000e4f0 function, a direct call to system was found executing the shell script /etc/scripts/dlcfg_hlper.sh, which may allow arbitrary command execution through carefully crafted HTTP requests.
- **Code Snippet:**
  ```
  0x0000ec88      c80308e3       movw r0, 0x83c8
  0x0000ec8c      020040e3       movt r0, 2                  ; 0x283c8 ; "/etc/scripts/dlcfg_hlper.sh" ; const char *string
  0x0000ec90      b9e9ffeb       bl sym.imp.system           ; int system(const char *string)
  ```
- **Keywords:** system, /etc/scripts/dlcfg_hlper.sh, HTTP_REFERER
- **Notes:** command_execution

---
### CGI-System-Call-2

- **File/Directory Path:** `N/A`
- **Location:** `htdocs/cgibin:0x0000edb4 (fcn.0000e4f0)`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** In the function fcn.0000e4f0, a direct call to system was found executing the shell script /etc/scripts/dongle_list_helper.sh. This operation may allow arbitrary command execution through carefully crafted HTTP requests.
- **Code Snippet:**
  ```
  0x0000edac      940408e3       movw r0, 0x8494
  0x0000edb0      020040e3       movt r0, 2                  ; 0x28494 ; "/etc/scripts/dongle_list_helper.sh" ; const char *string
  0x0000edb4      70e9ffeb       bl sym.imp.system           ; int system(const char *string)
  ```
- **Keywords:** system, /etc/scripts/dongle_list_helper.sh, HTTP_COOKIE
- **Notes:** command_execution

---
### CGI-Sprintf-Vuln

- **File/Directory Path:** `N/A`
- **Location:** `htdocs/cgibin:0x0000e6c8 (fcn.0000e4f0)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Multiple instances of sprintf usage for string formatting without length checks were found in the fcn.0000e4f0 function, potentially leading to buffer overflow vulnerabilities.
- **Code Snippet:**
  ```
  0x0000e6c0      0100a0e1       mov r0, r1                  ; char *s
  0x0000e6c4      0310a0e1       mov r1, r3                  ; const char *format
  0x0000e6c8      e2ebffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  ```
- **Keywords:** sprintf, HTTP_HOST, HTTP_USER_AGENT
- **Notes:** validate input length

---
