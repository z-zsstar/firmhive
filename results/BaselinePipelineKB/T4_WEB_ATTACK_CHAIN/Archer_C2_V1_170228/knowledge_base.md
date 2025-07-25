# Archer_C2_V1_170228 (5 alerts)

---

### vulnerability-httpd-rdp_action-004095d0

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x004095d0`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** At 0x004095d0, system command execution via rdp_action was discovered. If the parameters are controllable, it may lead to RCE. When handling actions like ACT_REBOOT, system commands are executed directly without validation. Attackers could trigger arbitrary command execution by crafting specific HTTP requests.
- **Keywords:** rdp_action, ACT_REBOOT
- **Notes:** Need to trace the source of the rdp_action parameter to confirm whether it comes directly from the HTTP request.

---
### vulnerability-httpd-strcpy-00408e74

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0x00408e74`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** An unverified strcpy call was identified at 0x00408e74, potentially causing buffer overflow. Attackers could trigger this vulnerability via specially crafted HTTP requests, leading to arbitrary code execution. Trigger condition: When the http_cgi_main function processes maliciously constructed HTTP requests, it directly copies input into a fixed-size buffer using strcpy without performing length validation.
- **Keywords:** strcpy, http_cgi_main, var_15ch
- **Notes:** Further verification is required to determine whether the source of var_15ch is directly from HTTP request parameters.

---
### vulnerability-httpd-http_cgi_main

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A risk has been identified in the sym.http_cgi_main function of the httpd program where user input is directly passed to dangerous functions. Attackers can trigger buffer overflow through specially crafted HTTP requests, potentially leading to arbitrary code execution. Trigger condition: When processing HTTP requests, user input is passed directly to dangerous functions like strcpy without sufficient validation.
- **Code Snippet:**
  ```
  iVar6 = sym.http_stream_fgets(*(*param_1 + 8),*param_1 + 0x14,pcVar11,iStack_38);
  ...
  (*pcVar12)(pcVar11 + iVar5 + -1,pcVar2);
  ```
- **Keywords:** sym.http_cgi_main, sym.imp.strcpy, sym.http_stream_fgets
- **Notes:** Verify the call sites of sym.http_stream_fgets and sym.http_parser_argIllustrate to confirm input validation status. Potentially related to the previously identified strcpy call at 0x00408e74.

---
### vulnerability-httpd-http_parser_main

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The issue of insufficient input length validation was identified in the sym.http_parser_main function. Attackers could potentially trigger buffer overflow or other memory corruption vulnerabilities by sending excessively long HTTP requests.
- **Keywords:** sym.http_parser_main, sym.http_parser_argIllustrate
- **Notes:** Track the source of the sym.http_parser_argIllustrate parameter to confirm whether it originates directly from the HTTP request.

---
### vulnerability-httpd-sprintf-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd:0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** A potential format string vulnerability was identified at 0xREDACTED_PASSWORD_PLACEHOLDER, where an attacker may control the format parameters. When the http_cgi_main function processes user input, it directly uses user-controllable data as the format parameter for sprintf without proper validation.
- **Keywords:** sprintf, http_cgi_main, var_70h
- **Notes:** Need to confirm whether var_70h comes directly from HTTP request parameters

---
