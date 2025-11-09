# R6400v2-V1.0.2.46_1.0.36 (4 alerts)

---

### HTTPD-SYSTEM-COMMAND-INJECTION

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/httpd:0x35fb4 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** The HTTP request parameters are used to construct system commands and executed via system() without sufficient validation, leading to a command injection vulnerability. Attackers can execute arbitrary commands by manipulating the HTTP parameters.
- **Code Snippet:**
  ```
  sym.imp.system(*0x35fb4);
  sym.imp.system(puVar12 + -0x508);
  ```
- **Keywords:** system, getenv, QUERY_STRING
- **Notes:** verify whether command construction includes filtering

---
### HTTP-QUERY-STRING-UNVALIDATED

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0x9f64 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The QUERY_STRING parameter is used to construct URLs and accessed via curl without sufficient validation, which may lead to SSRF vulnerabilities. Attackers could potentially access arbitrary internal services by controlling the QUERY_STRING parameter.
- **Code Snippet:**
  ```
  sym.imp.snprintf(uVar2,uVar3,"%s?t=%s&d=%s&c=%s",*(puVar5 + -100));
  sym.imp.curl_easy_perform(*(puVar5 + -0x28));
  ```
- **Keywords:** QUERY_STRING, snprintf, curl_easy_perform
- **Notes:** Verify if there is a whitelist restriction for the URL target

---
### HTTPD-UNSAFE-STRCPY

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/httpd:0x359c8 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** network_input
- **Code Snippet:**
  ```
  sym.imp.strcpy(iVar10,iVar5);
  sym.imp.strcpy(puVar12 + -0x308,iVar9);
  ```
- **Keywords:** strcpy, strncpy, URLHIDDEN
- **Notes:** Check the target buffer size

---
### HTTP-HEADER-UNSAFE-COPY

- **File/Directory Path:** `N/A`
- **Location:** `www/cgi-bin/genie.cgi:0xa0b8 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** The use of unvalidated strncpy in HTTP response header processing may lead to buffer overflow or response header injection. Particularly, there are risks when handling X-Error-Code and X-Error-Message.
- **Code Snippet:**
  ```
  sym.imp.strncpy(*(puVar5 + -0x24),*(puVar5 + -0x40),*(puVar5 + -0x44) - *(puVar5 + -0x40));
  ```
- **Keywords:** strncpy, X-Error-Code, X-Error-Message
- **Notes:** Check the target buffer size

---
