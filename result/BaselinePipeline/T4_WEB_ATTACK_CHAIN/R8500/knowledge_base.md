# R8500 (4 alerts)

---

### httpd-POST-user_accounts-buffer_overflow

- **File/Directory Path:** `usr/sbin/httpd`
- **Location:** `usr/sbin/httpd:0x0002a7f8`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** vulnerability
- **Code Snippet:**
  ```
  0x0002a7f8      f0452de9       push {r4, r5, r6, r7, r8, sl, lr}
  0x0002a7fc      e3dd4de2       sub sp, sp, 0x38c0
  0x0002a800      14d04de2       sub sp, sp, 0x14
  0x0002a804      0040a0e3       mov r4, 0
  0x0002a808      0050a0e1       mov r5, r0                  ; 0xc83f8 ; "fw_bks_block_type" ; arg1
  0x0002a80c      0260a0e1       mov r6, r2
  0x0002a810      030a8de2       add r0, s
  0x0002a814      032a8de2       add r2, s
  0x0002a818      e2ad8de2       add sl, var_3880h
  0x0002a81c      244082e5       str r4, [r2, 0x24]
  0x0002a820      38a08ae2       add sl, sl, 0x38
  0x0002a824      ff2fa0e3       mov r2, 0x3fc
  0x0002a828      0170a0e1       mov r7, r1                  ; arg2
  0x0002a82c      280080e2       add r0, r0, 0x28            ; void *s
  0x0002a830      0410a0e1       mov r1, r4                  ; int c
  0x0002a834      0380a0e1       mov r8, r3
  0x0002a838      458effeb       bl sym.imp.memset           ; void *memset(void *s, int c, size_t n)
  ```
- **Keywords:** fcn.0002a7f8, strcpy, sprintf, strcat, POST /oem/user_accounts
- **Notes:** vulnerability

---
### genie.cgi-curl-SSRF

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** vulnerability
- **Code Snippet:**
  ```
  curl_easy_setopt(CURL *handle, CURLoption option, parameter)
  ```
- **Keywords:** curl_easy_setopt, fcn.REDACTED_PASSWORD_PLACEHOLDER, var_40h, var_3ch, var_44h
- **Notes:** Implement strict URL whitelisting for all curl requests. Consider removing this functionality if not absolutely necessary.

---
### genie.cgi-snprintf-buffer_overflow

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In genie.cgi, the function fcn.REDACTED_PASSWORD_PLACEHOLDER uses snprintf to format URL parameters containing HTTP request variables (access REDACTED_PASSWORD_PLACEHOLDER, agent ID, etc.). While snprintf is safer than sprintf, improper size calculations could still lead to buffer overflows if input lengths aren't properly controlled.
- **Code Snippet:**
  ```
  snprintf(char *s, size_t size, const char *format, ...)
  ```
- **Keywords:** snprintf, fcn.REDACTED_PASSWORD_PLACEHOLDER, var_28h, var_30h, var_2ch
- **Notes:** vulnerability

---
### genie.cgi-strncpy-truncation

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0x00009ac4`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** vulnerability
- **Code Snippet:**
  ```
  strncpy(char *dest, const char *src, size_t n)
  ```
- **Keywords:** strncpy, fcn.REDACTED_PASSWORD_PLACEHOLDER, var_3ch, var_58h, var_5ch
- **Notes:** vulnerability

---
