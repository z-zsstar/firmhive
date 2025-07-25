# R9000 (4 alerts)

---

### buffer-overflow-proccgi-strcpy

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `www/cgi-bin/proccgi:0x888c`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The binary file proccgi contains a buffer overflow vulnerability. The function fcn.REDACTED_PASSWORD_PLACEHOLDER employs an unsafe strcpy operation and is invoked by the HTTP request handling function fcn.00008b38. An attacker can trigger a buffer overflow by crafting an excessively long HTTP parameter.
- **Code Snippet:**
  ```
  mov r1, r4; bl sym.imp.strcpy
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, strcpy, fcn.00008b38
- **Notes:** Further dynamic analysis is required to confirm actual exploitability.

---
### command-injection-RMT_invite.cgi-eval

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `www/cgi-bin/RMT_invite.cgi:3`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** The RMT_invite.cgi script contains a severe command injection vulnerability, where the output of proccgi is directly executed via eval without filtering the input parameters (FORM_TXT_remote_login and FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER). Attackers can inject arbitrary commands by crafting malicious HTTP parameters.
- **Code Snippet:**
  ```
  eval "\`/www/cgi-bin/proccgi $*\`"
  ```
- **Keywords:** eval, proccgi, FORM_TXT_remote_login, FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Further analysis is required to determine how proccgi processes input parameters in order to confirm injection possibilities.

---
### buffer-overflow-nvram-strcpy

- **File/Directory Path:** `bin/nvram`
- **Location:** `bin/nvram:0x87c4`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The nvram binary contains a strcpy call (address 0x87c4), likely used for processing configuration parameters. The lack of boundary checks may lead to buffer overflow vulnerabilities, particularly when input originates from HTTP parameters.
- **Keywords:** strcpy, 0x87c4
- **Notes:** buffer_overflow

---
### unsafe-input-RMT_invite.cgi-nvram

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `www/cgi-bin/RMT_invite.cgi:34`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In RMT_invite.cgi, user input (FORM_TXT_remote_login) is directly passed to the nvram set command, potentially allowing modification of system configurations (readycloud_user_admin). Although nvram may have input validation, directly passing user input poses risks.
- **Code Snippet:**
  ```
  ${nvram} set readycloud_user_admin=$FORM_TXT_remote_login
  ```
- **Keywords:** FORM_TXT_remote_login, nvram, readycloud_user_admin
- **Notes:** Verify the specific implementation and input validation of the nvram command

---
