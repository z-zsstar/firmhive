# R7500 (3 alerts)

---

### vulnerability-cgi-http_input-buffer_overflow

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `proccgi:0xREDACTED_PASSWORD_PLACEHOLDER (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** High-risk vulnerabilities found in file 'www/cgi-bin/proccgi': 1) Function fcn.REDACTED_PASSWORD_PLACEHOLDER directly copies the QUERY_STRING environment variable to a buffer using strcpy without length checking, posing a buffer overflow risk; 2) When reading POST data using fread, it solely relies on CONTENT_LENGTH without verifying the actual number of bytes read. These vulnerabilities can be exploited via carefully crafted HTTP requests and may lead to remote code execution.
- **Code Snippet:**
  ```
  strcpy(iVar5,iVar2);
  fread(iVar4,1,iVar5,iVar2);
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, QUERY_STRING, CONTENT_LENGTH, strcpy, fread, malloc, REQUEST_METHOD
- **Notes:** Triggering the vulnerability requires the attacker to control QUERY_STRING or POST data. It is recommended to check: 1) the actual allocated buffer size; 2) other functions using the same input; 3) how CGI parameters are mapped to environment variables.

---
### network_input-RMT_invite.cgi-http_params_direct_use

- **File/Directory Path:** `www/cgi-bin/RMT_invite.cgi`
- **Location:** `RMT_invite.cgi`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Multiple HTTP form parameters in the RMT_invite.cgi script were found to be directly used without adequate input validation or filtering, posing security risks. Specifically: 1) The FORM_TXT_remote_login and FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER parameters were directly used to construct JSON data and passed via pipe to readycloud_control.cgi; 2) Multiple REDACTED_PASSWORD_PLACEHOLDER parameters were directly used in nvram set commands. These parameters could be maliciously exploited for command injection or system configuration modification.
- **Code Snippet:**
  ```
  echo "{\"state\":\"1\",\"owner\":\"$FORM_TXT_remote_login\",\"REDACTED_PASSWORD_PLACEHOLDER\":\"$FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER\"}"|REQUEST_METHOD=PUT PATH_REDACTED_PASSWORD_PLACEHOLDER /www/cgi-bin/readycloud_control.cgi
  ```
- **Keywords:** FORM_TXT_remote_login, FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER, FORM_change_wan_pppoe_demand, FORM_change_wan_pptp_demand, FORM_change_wan_mulpppoe_demand, FORM_change_wan_l2tp_demand, readycloud_control.cgi, nvram
- **Notes:** Further analysis is required to examine how readycloud_control.cgi processes these input data in order to assess the complete attack surface. It is recommended to inspect all code paths that utilize HTTP form parameters.

---
### web-cgi-proccgi-http-param-processing

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `www/cgi-bin/proccgi: various addresses`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Multiple dangerous function calls for processing HTTP request parameters were identified in the CGI program 'proccgi'. Specific issues include:
1. Direct use of strcpy/strcmp to process HTTP GET/POST parameters (e.g., QUERY_STRING) obtained via getenv, without boundary checks
2. Direct use of strcpy to copy HTTP parameters, which may lead to buffer overflow
3. Output of unsanitized HTTP parameters using fprintf/fputc

Trigger condition: Attacker provides malicious input parameters through HTTP requests (GET/POST)
Security impact: Buffer overflow may result in remote code execution or service crash
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, fcn.000087c8, fcn.00008ac0, strcpy, getenv, strcmp, fprintf, fputc, REQUEST_METHOD, QUERY_STRING, CONTENT_LENGTH, proccgi, cgi-bin
- **Notes:** It is recommended to conduct dynamic testing to confirm the exploitability of the vulnerability. Other CGI scripts/binary files should be checked for similar issues. REDACTED_PASSWORD_PLACEHOLDER risk point: HTTP parameters are directly passed to dangerous functions without boundary checks.

---
