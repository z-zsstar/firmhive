# R6400v2-V1.0.2.46_1.0.36 (2 alerts)

---

### web-genie.cgi-snprintf-risk

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `genie.cgi:0x9794 (fcn.REDACTED_PASSWORD_PLACEHOLDER)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Security risks identified in snprintf calls within genie.cgi:
- Used to construct URLs containing HTTP request parameters and configuration data
- Buffer fixed at 2048 bytes with no explicit validation of input length
- Potential risks include buffer overflow and format string vulnerabilities
- Critical parameter sources:
  * `puVar5 + -100`: Base URL
  * `puVar5 + -0x10`: Access REDACTED_PASSWORD_PLACEHOLDER
  * `puVar5 + -0x18` and `puVar5 + -0x14`: Configuration values
- Attackers could trigger buffer overflow through carefully crafted HTTP requests
- **Code Snippet:**
  ```
  sym.imp.snprintf(uVar2,uVar3,"%s?t=%s&d=%s&c=%s",*(puVar5 + -100));
  ```
- **Keywords:** snprintf, puVar5, QUERY_STRING, fcn.REDACTED_PASSWORD_PLACEHOLDER, fcn.000093e4
- **Notes:** It is recommended to verify the input validation of the HTTP request parsing function (fcn.000093e4) and the data processing of the configuration reading function (fcn.0000a3c0).

---
### network_input-genie.cgi-snprintf_overflow

- **File/Directory Path:** `www/cgi-bin/genie.cgi`
- **Location:** `genie.cgi:0xREDACTED_PASSWORD_PLACEHOLDER fcn.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** In the function fcn.REDACTED_PASSWORD_PLACEHOLDER of the genie.cgi file, the HTTP parameters t, d, and c are used to construct a URL in the format '%s?t=%s&d=%s&c=%s'. When the snprintf function is called, the destination buffer size is 2048 bytes (0x800). The function lacks proper validation of input parameter length and content, which may lead to the following security issues:
1. Buffer overflow risk: If the total length of parameters exceeds the buffer size
2. Format string vulnerability: If parameters contain format specifiers

These parameters may originate from memory locations after HTTP request parsing, indicating this is a typical case where web interface input is directly passed to dangerous functions.
- **Code Snippet:**
  ```
  sym.imp.snprintf(uVar2,uVar3,"%s?t=%s&d=%s&c=%s",*(puVar5 + -100));
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, snprintf, t=%s, d=%s, c=%s, 0x800, 0xREDACTED_PASSWORD_PLACEHOLDER, genie.cgi, HTTP_parameters
- **Notes:** Although the buffer size is relatively large (2048 bytes), the lack of input validation could still be exploited if an attacker gains control over the contents of parameters t, d, and c. Further analysis of the source functions for these parameters is required to comprehensively assess the risk.

---
