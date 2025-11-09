# R7500 (5 alerts)

---

### vulnerability-RMT_invite.cgi-command_injection

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `www/cgi-bin/RMT_invite.cgi:14-15`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** In RMT_invite.cgi, the HTTP parameters FORM_TXT_remote_login and FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER are directly used to construct a JSON string and passed to readycloud_control.cgi without any input validation or escaping. Attackers may achieve command injection or JSON injection by carefully crafting login name or REDACTED_PASSWORD_PLACEHOLDER parameters.
- **Code Snippet:**
  ```
  echo "{\"state\":\"1\",\"owner\":\"$FORM_TXT_remote_login\",\"REDACTED_PASSWORD_PLACEHOLDER\":\"$FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER\"}"|REQUEST_METHOD=PUT PATH_REDACTED_PASSWORD_PLACEHOLDER /www/cgi-bin/readycloud_control.cgi
  ```
- **Keywords:** FORM_TXT_remote_login, FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER, readycloud_control.cgi, REQUEST_METHOD=PUT, PATH_REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Further analysis is required on how readycloud_control.cgi processes these input parameters.

---
### vulnerability-proccgi-strcpy_buffer_overflow

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `www/cgi-bin/proccgi:0x87f0 fcn.000087c8`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A buffer overflow vulnerability was discovered in function fcn.000087c8. This function uses strcpy to copy HTTP request parameters without properly restricting input length. Attackers can trigger heap overflow by crafting excessively long QUERY_STRING or POST data.
- **Code Snippet:**
  ```
  mov r1, r5; bl sym.imp.strcpy
  ```
- **Keywords:** fcn.000087c8, strcpy, QUERY_STRING, POST
- **Notes:** The vulnerability is triggered via HTTP environment variables. It is necessary to inspect all paths invoking fcn.000087c8.

---
### vulnerability-proccgi-query_string_injection

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `www/cgi-bin/proccgi:0x88dc-0x88ec`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Identified paths that directly process QUERY_STRING and POST data, where these parameters may ultimately be passed to dangerous functions.
- **Code Snippet:**
  ```
  ldr r0, "QUERY_STRING"; bl sym.imp.getenv; b fcn.000087c8
  ```
- **Keywords:** QUERY_STRING, REQUEST_METHOD, fcn.000088dc, fcn.00008ac0
- **Notes:** confirmed the complete call chain from HTTP parameters to strcpy

---
### vulnerability-RMT_invite.cgi-config_tampering

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `www/cgi-bin/RMT_invite.cgi:10-40`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** In RMT_invite.cgi, the HTTP parameter FORM_submit_flag controls the program flow, and multiple REDACTED_PASSWORD_PLACEHOLDER parameters are directly used for nvram configuration settings without sufficient validation. Attackers may modify these parameters to achieve configuration tampering.
- **Code Snippet:**
  ```
  case "$FORM_submit_flag" in
      register_user)
          ...
          if [ "$FORM_change_wan_pppoe_demand" = "1" ]; then
              ${nvram} set wan_pppoe_demand=0;
          fi
  ```
- **Keywords:** FORM_submit_flag, FORM_change_wan_pppoe_demand, FORM_change_wan_pptp_demand, FORM_change_wan_mulpppoe_demand, FORM_change_wan_l2tp_demand, nvram
- **Notes:** Check the security restrictions of the nvram command

---
### vulnerability-proccgi-content_length_overflow

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `www/cgi-bin/proccgi:0x8878-0x8894`
- **Risk Score:** 7.0
- **Confidence:** 6.75
- **Description:** The HTTP request handler function fcn.REDACTED_PASSWORD_PLACEHOLDER fails to properly validate CONTENT_LENGTH, which may lead to integer overflow or memory exhaustion attacks.
- **Code Snippet:**
  ```
  bl sym.imp.getenv; bl sym.imp.atoi; bl sym.imp.malloc
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, CONTENT_LENGTH, malloc, atoi
- **Notes:** Verify the maximum allowed value of CONTENT_LENGTH

---
