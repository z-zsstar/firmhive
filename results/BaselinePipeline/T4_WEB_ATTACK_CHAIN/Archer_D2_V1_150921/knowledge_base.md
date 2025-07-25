# Archer_D2_V1_150921 (5 alerts)

---

### vulnerability-httpd-unsafe-string-functions

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** buffer_overflow
- **Code Snippet:**
  ```
  Not provided in findings.
  ```
- **Keywords:** sym.imp.strcpy, sym.imp.strncpy, sym.imp.sprintf, fcn.004015d0, fcn.REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** buffer_overflow

---
### vulnerability-upnpd-system-calls

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `usr/bin/upnpd: 0x401f90, 0x403408, 0x4075b4, 0x4098a0`
- **Risk Score:** 8.5
- **Confidence:** 7.25
- **Description:** In the upnpd binary, four instances of the system() function were found (0x401f90, 0x403408, 0x4075b4, 0x4098a0). These calls may execute system commands. The parameters passed to these functions need further analysis to determine if they include user-controlled input without proper sanitization, which could lead to command injection vulnerabilities.
- **Code Snippet:**
  ```
  Not provided in findings.
  ```
- **Keywords:** system, UpnpInit, REDACTED_PASSWORD_PLACEHOLDER, UpnpNotifyExt
- **Notes:** Dynamic analysis is required to confirm parameter controllability. Focus on UPnP request handling logic, especially SOAP action processing.

---
### vulnerability-httpd-multipart-form

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x4038ec`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In httpd, the function fcn.004038ec processes HTTP multipart form data, extracting 'name' and 'filename' parameters without adequate length validation. This could enable attackers to trigger buffer overflows by supplying excessively long parameters.
- **Code Snippet:**
  ```
  fcn.004015d0(puVar4,pcVar3,0x100);
  ```
- **Keywords:** fcn.004038ec, fcn.004015d0, fcn.00405d84, Content-Disposition, name, filename
- **Notes:** Verify maximum parameter length limits and boundary checks.

---
### vulnerability-httpd-socket-data

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `usr/bin/httpd:0x402424`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** buffer_overflow
- **Code Snippet:**
  ```
  iVar3 = fcn.REDACTED_PASSWORD_PLACEHOLDER(piVar11,&uStack_e0,1,2);
  ```
- **Keywords:** fcn.REDACTED_PASSWORD_PLACEHOLDER, fcn.REDACTED_PASSWORD_PLACEHOLDER, fcn.REDACTED_PASSWORD_PLACEHOLDER, ioctl, setsockopt
- **Notes:** buffer_overflow

---
### vulnerability-upnpd-strcpy

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `usr/bin/upnpd: sym.imp.strcpy`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** buffer_overflow
- **Code Snippet:**
  ```
  Not provided in findings.
  ```
- **Keywords:** strcpy, ixmlNode_getNodeValue, ixmlParseBuffer
- **Notes:** buffer_overflow

---
