# TL-WA701ND_V2_140324 (3 alerts)

---

### vulnerability-httpd-system

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x0040d1a8 sym.fcn.0040d15c`
- **Risk Score:** 9.0
- **Confidence:** 8.25
- **Description:** A vulnerability was identified in the HTTP authentication handler where user input is directly concatenated into system commands, potentially leading to command injection. The trigger conditions include specific parameters in HTTP authentication requests. Potential impacts include remote command execution.
- **Code Snippet:**
  ```
  Not provided in the original findings.
  ```
- **Keywords:** system, HTTP_AUTH, sym.fcn.0040d15c
- **Notes:** It is recommended to conduct dynamic testing to verify the exploitability of the vulnerability. Special attention should be paid to command injection vulnerabilities (CWE-78).

---
### vulnerability-httpd-strcpy

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x0040b7d4 sym.fcn.0040b7a4`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** In the function sym.fcn.0040b7a4, an unvalidated HTTP parameter is directly passed to the strcpy function. Attackers may exploit this by crafting malicious HTTP request parameters to trigger a buffer overflow. Trigger conditions include specific parameters in HTTP GET requests. Potential impacts include remote code execution or service crashes.
- **Code Snippet:**
  ```
  Not provided in the original findings.
  ```
- **Keywords:** sym.fcn.0040b7a4, strcpy, HTTP_GET_PARAM
- **Notes:** It is recommended to conduct dynamic testing to verify the exploitability of the vulnerability. Focus on buffer overflow vulnerabilities (CWE-120).

---
### vulnerability-httpd-sprintf

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x0040c310 sym.fcn.0040c2a8`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** A vulnerability was identified in the function handling HTTP POST requests where the use of sprintf to format user input could lead to a format string vulnerability. Trigger conditions include specific data within HTTP POST requests. Potential impacts include information disclosure or remote code execution.
- **Code Snippet:**
  ```
  Not provided in the original findings.
  ```
- **Keywords:** sprintf, HTTP_POST_DATA, sym.fcn.0040c2a8
- **Notes:** It is recommended to conduct dynamic testing to verify the exploitability of the vulnerability. Special attention should be paid to format string vulnerabilities (CWE-134).

---
