# DIR-868L_fw_revA_1-12_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (3 alerts)

---

### httpd-command-injection-1df28

- **File/Directory Path:** `N/A`
- **Location:** `sbin/httpd:0x1df28 (unknown_function)`
- **Risk Score:** 9.5
- **Confidence:** 8.75
- **Description:** A command injection vulnerability was discovered at address 0x1df28 in the httpd binary. The system function is called using unvalidated user input as parameters, allowing attackers to execute arbitrary system commands by crafting specific HTTP requests. This vulnerability can be exploited without authentication and poses a high severity risk.
- **Code Snippet:**
  ```
  call sym.imp.system
  ```
- **Keywords:** system, command_injection, http_request_processing
- **Notes:** Further confirmation is required regarding the specific HTTP request handling process and parameter sources.

---
### smbd-command-injection-18e7b0

- **File/Directory Path:** `N/A`
- **Location:** `sbin/smbd:0x18e7b0 (fcn.0018e6e4)`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** A potential command injection vulnerability was identified at address 0x18e7b0 in the smbd binary. The system function is called using unvalidated user input (pcVar5) as a parameter, which could allow attackers to execute arbitrary system commands by crafting specific SMB requests.
- **Code Snippet:**
  ```
  iVar1 = sym.imp.system(pcVar5);
  ```
- **Keywords:** system, command_injection, SMB_request_processing
- **Notes:** Further confirmation is required regarding the specific SMB request handling process and parameter sources.

---
### insecure-fw-check-script

- **File/Directory Path:** `N/A`
- **Location:** `etc/events/checkfw.sh`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** The /etc/events/checkfw.sh script contains multiple security issues: 1) Using insecure wget to download firmware information without verifying server certificates; 2) Failing to perform proper validation when parsing XML input; 3) Potential vulnerability to DNS spoofing or man-in-the-middle attacks leading to malicious firmware injection.
- **Code Snippet:**
  ```
  wget_string="http://"$srv$reqstr"?model=$model\_$global\_FW\_$buildver\_$MAC"
  wget  $wget_string -O $fwinfo
  ```
- **Keywords:** wget, firmware_update, xml_parsing, dns_spoofing
- **Notes:** It is recommended to add HTTPS certificate verification and XML input validation.

---
