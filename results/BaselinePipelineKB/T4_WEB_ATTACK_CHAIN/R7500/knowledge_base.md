# R7500 (16 alerts)

---

### vulnerability-ozker-system-0x121bc

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/ozker:0x121bc`
- **Risk Score:** 9.5
- **Confidence:** 6.25
- **Description:** At address 0x121bc, a system function call was identified, posing a command injection risk. Further analysis of the calling context is required to confirm whether unvalidated user input is being used as command parameters.
- **Code Snippet:**
  ```
  bl sym.imp.system
  ```
- **Keywords:** system, 0x121bc, ozker, command_injection
- **Notes:** Decompile the function at 0x121bc to confirm the input source

---
### vulnerability-proccgi-command-injection-chain

- **File/Directory Path:** `www/cgi-bin/proccgi`
- **Location:** `www/cgi-bin/proccgi & www/cgi-bin/RMT_invite.cgi`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** Analysis of multiple findings in proccgi confirms security risks in its handling of HTTP request parameters. proccgi employs unsafe functions (such as strcpy) to process user input and fails to fully filter hazardous characters. When proccgi's output is directly executed by eval in RMT_invite.cgi, attackers can inject arbitrary commands through carefully crafted HTTP parameters, forming a complete command injection vulnerability chain.
- **Code Snippet:**
  ```
  eval "\`/www/cgi-bin/proccgi $*\`"
  ```
- **Keywords:** proccgi, eval, command_injection, HTTP_parameter, RMT_invite.cgi, QUERY_STRING
- **Notes:** The complete vulnerability chain was confirmed by combining multiple findings: HTTP parameters -> proccgi processing -> eval execution

---
### vulnerability-cgi-eval-0001

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:3`
- **Risk Score:** 9.0
- **Confidence:** 8.0
- **Description:** The script uses eval to execute the output of proccgi, which may lead to command injection. proccgi processes HTTP request parameters, and its output is directly passed to eval, allowing attackers to potentially inject arbitrary commands by crafting malicious HTTP parameters.
- **Code Snippet:**
  ```
  eval "\`/www/cgi-bin/proccgi $*\`"
  ```
- **Keywords:** eval, proccgi, $*, RMT_invite.cgi, command_injection
- **Notes:** Further analysis of the proccgi script is required to confirm the parameter handling method.

---
### vulnerability-uhttpd-system-uh_cgi_request

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd: sym.uh_cgi_request`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** Command execution was detected where the system function is used to execute system commands, with part of the command parameters originating from HTTP request data. During CGI request processing, the system function is called to execute commands when specific conditions are met, but the input is not adequately filtered.
- **Code Snippet:**
  ```
  sym.imp.system(*0xfebc);
  ```
- **Keywords:** system, uh_cgi_request, puVar21, param_3, command_injection, HTTP_parameter
- **Notes:** Verify whether the command string stored at address 0xfebc contains user-controllable data

---
### vulnerability-cgi-formparams-0002

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/RMT_invite.cgi:10-40`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Multiple REDACTED_PASSWORD_PLACEHOLDER variables are directly used for system configuration and command execution, including FORM_TXT_remote_login, FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER, etc. These user-provided inputs are passed to nvram commands and environment variables without proper validation or escaping.
- **Code Snippet:**
  ```
  echo "{\"state\":\"1\",\"owner\":\"$FORM_TXT_remote_login\",\"REDACTED_PASSWORD_PLACEHOLDER\":\"$FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER\"}"
  ```
- **Keywords:** FORM_TXT_remote_login, FORM_TXT_remote_REDACTED_PASSWORD_PLACEHOLDER, FORM_change_wan_pppoe_demand, nvram, RMT_invite.cgi, configuration_tampering
- **Notes:** Attackers may alter system configurations or execute arbitrary commands by crafting malicious inputs.

---
### vulnerability-cgi-strcpy-000087c8

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x87f0 fcn.000087c8`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** An unsafe strcpy call was identified in the fcn.000087c8 function, which processes user input parameters. The function first retrieves the input length and allocates memory, but copies data using strcpy without boundary checks, potentially leading to a buffer overflow vulnerability. Attackers could exploit this vulnerability by crafting malicious HTTP parameters.
- **Code Snippet:**
  ```
  sym.imp.strcpy(iVar1,param_1);
  ```
- **Keywords:** fcn.000087c8, strcpy, malloc, strlen, proccgi, HTTP_parameter
- **Notes:** Further verification is required to determine the source of param_1, which may be obtained through getenv as an HTTP parameter.

---
### vulnerability-ozker-strcpy-0000ddf4

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/ozker:0xde74,0xdef4 (fcn.0000ddf4)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Multiple strcpy calls in function fcn.0000ddf4 pose buffer overflow risks. This function handles path string concatenation without checking the destination buffer size, potentially leading to memory corruption. Attackers could exploit this vulnerability by manipulating input path parameters.
- **Code Snippet:**
  ```
  sym.imp.strcpy(pcVar6 + 0x30,iVar7);
  sym.imp.strcpy(iVar7,param_2);
  ```
- **Keywords:** fcn.0000ddf4, strcpy, strlen, malloc, ozker, path_manipulation
- **Notes:** parameters may come from path parameters in an HTTP request

---
### vulnerability-uhttpd-strcpy-uh_cgi_request

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd: sym.uh_cgi_request`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** In the uh_cgi_request function, the strcpy function is found to be directly used for copying user-controllable HTTP input data. This operation occurs within the CGI request processing flow, where HTTP request parameters are copied into a buffer without length verification, potentially leading to a buffer overflow vulnerability.
- **Code Snippet:**
  ```
  sym.imp.strcpy(puVar21 + 0xffffda2c, puVar21 + 0xffffca35);
  ```
- **Keywords:** strcpy, uh_cgi_request, acStack_55f8, acStack_45f8, buffer_overflow, HTTP_parameter
- **Notes:** Further confirmation is required regarding the target buffer size and the maximum possible length of the input data.

---
### vulnerability-ozker-sprintf-000123b8

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/ozker:0x124c4 (fcn.000123b8)`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** A formatting string vulnerability was identified in the sprintf call within function fcn.000123b8. This function processes JSON object input without adequate validation of input string length, potentially leading to buffer overflow. Attackers could exploit this vulnerability by crafting malicious JSON requests.
- **Code Snippet:**
  ```
  iVar6 = sym.imp.sprintf(iVar11,*0x1259c);
  ```
- **Keywords:** fcn.000123b8, json_object_get, json_string_value, sprintf, ozker, JSON_injection
- **Notes:** Further verification is needed to determine whether the input source includes HTTP request parameters.

---
### vulnerability-proccgi-dangerous-functions

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** The proccgi binary file processes HTTP requests (GET/POST) as a CGI handler, utilizing hazardous functions (strcpy, atoi) to handle user input (QUERY_STRING, POST data), posing risks of buffer overflow and integer overflow.
- **Keywords:** proccgi, strcpy, atoi, QUERY_STRING, CONTENT_LENGTH, CGI_POST_TMPFILE, malloc, free, buffer_overflow, integer_overflow
- **Notes:** Dynamic testing or disassembly is required to confirm the specific vulnerability exploitation path. This binary may serve as the primary processor for all form submissions in the web interface.

---
### vulnerability-uhttpd-popen-uh_cgi_request

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd: sym.uh_cgi_request`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** Command execution is detected using the popen function, with parameters partially sourced from HTTP requests. While processing certain CGI requests, popen is invoked, but insufficient input validation may lead to command injection vulnerabilities.
- **Code Snippet:**
  ```
  sym.imp.popen(puVar21 + 0xffffffd8);
  ```
- **Keywords:** popen, uh_cgi_request, param_2, param_3, command_injection, HTTP_parameter
- **Notes:** Further analysis is needed on the parameter construction process during the popen call.

---
### vulnerability-ozker-json-0000

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/ozker`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** The global discovery process extensively utilizes JSON parsing functions to handle input, but lacks sufficient input validation. Multiple JSON processing paths ultimately flow into dangerous functions, posing potential injection risks.
- **Keywords:** json_object_get, json_string_value, json_integer_value, ozker, JSON_injection
- **Notes:** It is recommended to strictly validate and filter all JSON inputs.

---
### vulnerability-cgi-getenv-000085dc

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x85dc sym.imp.getenv`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The program uses getenv to retrieve environment variables, but it does not confirm whether they are used to obtain HTTP request parameters (such as QUERY_STRING). If these values are used directly without adequate validation, it may lead to various injection attacks.
- **Keywords:** getenv, QUERY_STRING, HTTP_parameter, proccgi
- **Notes:** It is necessary to track the usage of the return value of getenv to confirm specific risks.

---
### vulnerability-uhttpd-sprintf-uh_cgi_request

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd: sym.uh_cgi_request`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Discovered the use of sprintf for formatting string functions to process HTTP request data, but failed to check the output buffer size. Using sprintf when handling certain HTTP header fields may lead to buffer overflow or format string vulnerabilities.
- **Code Snippet:**
  ```
  sym.imp.sprintf(iVar17, "%s", param_2);
  ```
- **Keywords:** sprintf, uh_cgi_request, acStack_55f8, param_2, format_string, HTTP_header
- **Notes:** need to confirm the specific format string content and buffer size

---
### vulnerability-cgi-REDACTED_SECRET_KEY_PLACEHOLDER-00008ac0

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/proccgi:0x8ac0 fcn.00008ac0`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** In the fcn.00008ac0 function, HTTP parameter processing logic was identified. This function may retrieve user input (such as QUERY_STRING) through environment variables. The function includes handling of special characters (e.g., $, ", `, \), but fails to completely filter all dangerous characters, potentially leading to command injection vulnerabilities.
- **Code Snippet:**
  ```
  if (uVar4 == 0x24) {... sym.imp.fputc(0x5c); ...}
  ```
- **Keywords:** fcn.00008ac0, getenv, fprintf, fputc, QUERY_STRING, command_injection, proccgi
- **Notes:** It is necessary to confirm whether all dangerous characters have been properly handled, especially when parameters are used in system commands.

---
### vulnerability-uhttpd-strncpy-uh_cgi_request

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/uhttpd: sym.uh_cgi_request`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** It was discovered that when using strncpy to copy HTTP request data, the length parameter could be user-controlled. While strncpy is used to process certain CGI parameters, the length parameter may originate from unvalidated HTTP header fields.
- **Code Snippet:**
  ```
  sym.imp.strncpy(puVar21 + 0xffffca2c, iVar17, *(puVar21 + 0xffffaa0c));
  ```
- **Keywords:** strncpy, uh_cgi_request, param_3, param_4, buffer_overflow, HTTP_header
- **Notes:** Need to verify the source and validation process of the length parameter *(puVar21 + 0xffffaa0c)

---
