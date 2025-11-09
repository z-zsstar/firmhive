# R6400v2-V1.0.2.46_1.0.36 (5 alerts)

---

### genie.cgi-command-injection

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0x9f6c (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** A severe command injection vulnerability was discovered in genie.cgi. The program retrieves the QUERY_STRING environment variable via getenv and directly uses it to construct system commands without validation, which are then executed via popen. Attackers can inject arbitrary commands by crafting specific HTTP query parameters. The specific execution path is: getenv("QUERY_STRING") -> fcn.REDACTED_PASSWORD_PLACEHOLDER -> fcn.0000ac68 -> popen().
- **Code Snippet:**
  ```
  uVar2 = sym.imp.getenv("QUERY_STRING");
  ...
  fcn.0000ac68("internet set connection genieremote 1",puVar3 + -8,pcVar2);
  ```
- **Keywords:** QUERY_STRING, getenv, fcn.REDACTED_PASSWORD_PLACEHOLDER, fcn.0000ac68, popen, internet set connection genieremote 1
- **Notes:** It is necessary to check all instances where QUERY_STRING is used for potential command injection vulnerabilities. Implementing strict input validation and command whitelisting mechanisms is recommended.

---
### RMT_invite.cgi-eval-injection

- **File/Directory Path:** `opt/remote/bin/RMT_invite.cgi`
- **Location:** `opt/remote/bin/RMT_invite.cgi:3`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** A severe eval command injection vulnerability was discovered in RMT_invite.cgi. The script uses eval to execute the output of proccgi, and the output of proccgi processing HTTP input may contain malicious commands. Attackers can execute arbitrary commands by crafting specially crafted HTTP requests.
- **Code Snippet:**
  ```
  eval \`proccgi $*\`
  ```
- **Keywords:** eval, proccgi, $*, FORM_TXT_remote_login, FORM_TXT_remote_password
- **Notes:** command_injection

It is necessary to analyze the proccgi script to determine input sanitization status, and it is recommended to completely avoid using eval to execute external inputs.

---
### genie.cgi-format-string

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0x95b4 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A format string vulnerability was discovered in genie.cgi. The function fcn.REDACTED_PASSWORD_PLACEHOLDER uses snprintf to construct a URL query string ('%s?t=%s&d=%s&c=%s'), where the parameters come from HTTP requests without length validation. An attacker could potentially cause buffer overflow or memory corruption through carefully crafted query parameters.
- **Code Snippet:**
  ```
  sym.imp.snprintf(uVar2,uVar3,"%s?t=%s&d=%s&c=%s",*(puVar5 + -100));
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, snprintf, %s?t=%s&d=%s&c=%s, QUERY_STRING, var_28h, var_30h, var_2c
- **Notes:** Validate the maximum length limit of input parameters and enforce strict format string control.

---
### genie.cgi-http-header-injection

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0x9c38 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** An HTTP response header injection vulnerability was discovered in genie.cgi. The program directly constructs HTTP response headers (Status/X-Error-Code/X-Error-Message) using user-supplied parameters without proper encoding or filtering, which may lead to HTTP response splitting attacks, cache poisoning, or cross-site scripting attacks.
- **Code Snippet:**
  ```
  sym.imp.printf("X-Error-Code: %d\r\n",*(puVar5 + -8));
  ```
- **Keywords:** Status, X-Error-Code, X-Error-Message, printf, fcn.REDACTED_PASSWORD_PLACEHOLDER, strstr
- **Notes:** Strict encoding and validation must be applied to all HTTP response header values.

---
### genie.cgi-buffer-overflow

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `www/cgi-bin/genie.cgi:0x999c,0x9ac4,0x9b7c (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Multiple instances of unsafe strncpy usage were identified in genie.cgi, which could lead to buffer overflows or improperly terminated strings. Particularly when processing HTTP response data, the copy length is controlled by user input without verification of the destination buffer size.
- **Code Snippet:**
  ```
  sym.imp.strncpy(*(puVar5 + -0x24),*(puVar5 + -0x40),*(puVar5 + -0x44) - *(puVar5 + -0x40));
  ```
- **Keywords:** strncpy, fcn.REDACTED_PASSWORD_PLACEHOLDER, var_3ch, var_58h, var_5ch, X-Error-Code, X-Error-Message
- **Notes:** It is necessary to check whether the buffer size parameters of all strncpy calls are reasonable and ensure proper string termination.

---
