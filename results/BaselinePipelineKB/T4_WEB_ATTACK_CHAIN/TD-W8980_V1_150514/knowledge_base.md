# TD-W8980_V1_150514 (2 alerts)

---

### dangerous-functions

- **File/Directory Path:** `N/A`
- **Location:** `0x004015a0, 0xREDACTED_PASSWORD_PLACEHOLDER, 0xREDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** The program was found to use dangerous functions such as strcpy and sprintf, but it has not been confirmed whether they directly process unverified user input. These functions may lead to buffer overflow vulnerabilities when lacking boundary checks.
- **Code Snippet:**
  ```
  N/A (binary analysis)
  ```
- **Keywords:** sym.imp.strcpy, sym.imp.sprintf, sym.imp.strcat
- **Notes:** It is necessary to track the calling context of these functions to verify whether they handle user input from HTTP requests.

---
### web-cgi-endpoints

- **File/Directory Path:** `N/A`
- **Location:** `httpd binary`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** Multiple CGI endpoint handler functions were identified in the httpd binary, including /cgi/softup, /cgi/confup, etc. These endpoints may process user input but lack detailed analysis data. Further dynamic analysis is required to confirm potential command injection or buffer overflow vulnerabilities.
- **Code Snippet:**
  ```
  N/A (binary analysis)
  ```
- **Keywords:** /cgi/softup, /cgi/confup
- **Notes:** Since the binary has been stripped, function names and symbol information are missing, limiting static analysis. It is recommended to perform dynamic testing to verify the security of these CGI endpoints.

---
