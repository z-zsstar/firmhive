# _XR500-V2.1.0.4.img.extracted (4 alerts)

---

### vulnerability-RMT_invite-eval

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `www/cgi-bin/RMT_invite.cgi:3`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** An eval execution of the external command `/www/cgi-bin/proccgi $*` was found on line 3 of 'www/cgi-bin/RMT_invite.cgi', where `$*` contains unfiltered user input. This may lead to a command injection vulnerability, allowing attackers to execute arbitrary commands by crafting malicious HTTP parameters.
- **Code Snippet:**
  ```
  eval "\`/www/cgi-bin/proccgi $*\`"
  ```
- **Keywords:** eval, proccgi, $*
- **Notes:** Further analysis of the proccgi script is required to determine the input handling method.

---
### vulnerability-uhttpd-strcpy

- **File/Directory Path:** `usr/sbin/uhttpd`
- **Location:** `usr/sbin/uhttpd:0x108ec sym.do_uh_cgi_request`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** In the 'do_uh_cgi_request' function of 'usr/sbin/uhttpd', an unsafe usage of strcpy() was identified, where user-controlled input is copied into a fixed-size stack buffer without length validation. This could potentially lead to buffer overflow attacks, resulting in arbitrary code execution.
- **Code Snippet:**
  ```
  0x000108ec      e2e4ffeb       bl sym.imp.strcpy
  ```
- **Keywords:** strcpy, do_uh_cgi_request, sp+0x3040
- **Notes:** The target buffer is located on the stack, and its size is not validated against the length of the source input. An attacker can exploit this vulnerability by sending a specially crafted HTTP request.

---
### vulnerability-proccgi-strcpy

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `www/cgi-bin/proccgi:0x87f0 fcn.000087c8`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** An unchecked strcpy call was found in function fcn.000087c8 of 'www/cgi-bin/proccgi'. This function receives an external parameter (param_1) and directly passes it to strcpy, which may lead to buffer overflow. The parameter source may include HTTP request parameters, allowing attackers to overwrite memory with carefully crafted input, potentially executing arbitrary code or causing program crashes.
- **Code Snippet:**
  ```
  sym.imp.strcpy(iVar1,param_1);
  ```
- **Keywords:** fcn.000087c8, strcpy, param_1
- **Notes:** Further verification is required to determine whether param_1 originates from HTTP request parameters. It is recommended to inspect the parent function that calls fcn.000087c8.

---
### vulnerability-RMT_invite-json_injection

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `www/cgi-bin/RMT_invite.cgi:15,20,50`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** In 'www/cgi-bin/RMT_invite.cgi', unfiltered user inputs $FORM_TXT_remote_login and $FORM_TXT_remote_password are directly passed to readycloud_control.cgi (lines 15, 20, 50). Although transmitted via pipeline, potential parameter injection risks still exist.
- **Code Snippet:**
  ```
  echo "{\"state\":\"1\",\"owner\":\"$FORM_TXT_remote_login\",\"REDACTED_PASSWORD_PLACEHOLDER\":\"$FORM_TXT_remote_password\"}"|REQUEST_METHOD=PUT PATH_REDACTED_PASSWORD_PLACEHOLDER /www/cgi-bin/readycloud_control.cgi
  ```
- **Keywords:** FORM_TXT_remote_login, FORM_TXT_remote_password, readycloud_control.cgi
- **Notes:** It is necessary to check how readycloud_control.cgi processes these JSON data.

---
