# _US_AC18V1.0BR_V15.03.05.05_multi_TD01.bin.extracted (2 alerts)

---

### weak-user-authentication

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER, etc_ro/shadow`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** The system contains multiple users with UID 0 (REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, user), and their passwords use weak encryption (DES/MD5). The shadow file is incomplete, with some REDACTED_PASSWORD_PLACEHOLDER hashes stored in the REDACTED_PASSWORD_PLACEHOLDER file. Attackers can exploit these vulnerabilities for privilege escalation.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, shadow, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, DES, MD5, UID
- **Notes:** Verify whether these accounts are accessible via web services. Check if any services use these credentials for authentication.

---
### httpd-system-calls

- **File/Directory Path:** `N/A`
- **Location:** `bin/httpd:0x4f6c8 (sym.TendaTelnet), 0x3d5d8 (fcn.0003d4a0)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The HTTP service (bin/httpd) contains multiple system/doSystemCmd calls for executing system commands. Some invocations involve dynamically constructed command strings, posing potential command injection risks. Particular attention should be paid to: 1) The 'telnetd -b %s &' command in the TendaTelnet function; 2) Command execution in multiple CGI handler functions. While no direct vulnerability evidence was found, there is a noticeable lack of explicit input validation mechanisms.
- **Code Snippet:**
  ```
  0x0004f6c8      44fdfeeb       bl sym.imp.system           ; int system(const char *string)
  0x0004f6e0      12fffeeb       bl sym.imp.doSystemCmd
  ```
- **Keywords:** system, doSystemCmd, telnetd, killall, GetValue, TendaTelnet, webs_Tenda_CGI_BIN_Handler
- **Notes:** Further validation is required for the input source and filtering mechanism of GetValue. Check whether any user-controllable parameters can influence command construction.

---
