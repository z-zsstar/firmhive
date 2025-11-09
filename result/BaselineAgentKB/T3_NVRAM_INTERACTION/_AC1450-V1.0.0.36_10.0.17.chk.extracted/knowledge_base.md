# _AC1450-V1.0.0.36_10.0.17.chk.extracted (1 alerts)

---

### httpd-nvram-operations

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/httpd:0x21aa4-0x21ac8`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** The operation of setting dynamic DNS-related NVRAM variables was discovered in the httpd binary, including the REDACTED_PASSWORD_PLACEHOLDER (ddns_REDACTED_PASSWORD_PLACEHOLDER), REDACTED_PASSWORD_PLACEHOLDER (ddns_REDACTED_PASSWORD_PLACEHOLDER), and wildcard settings (ddns_wildcard). Storing passwords in plaintext within NVRAM may pose security risks.
- **Code Snippet:**
  ```
  bl sym.imp.nvram_set (HIDDENddns_REDACTED_PASSWORD_PLACEHOLDER)
  bl sym.imp.nvram_set (HIDDENddns_REDACTED_PASSWORD_PLACEHOLDER)
  bl sym.imp.nvram_set (HIDDENddns_wildcard)
  ```
- **Keywords:** ddns_REDACTED_PASSWORD_PLACEHOLDER, ddns_REDACTED_PASSWORD_PLACEHOLDER, ddns_wildcard, nvram_set
- **Notes:** Passwords are stored in plaintext; if NVRAM data is leaked, credentials may be compromised. It is recommended to check whether these values are used for sensitive operations.

---
