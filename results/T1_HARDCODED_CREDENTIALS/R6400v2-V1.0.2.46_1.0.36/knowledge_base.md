# R6400v2-V1.0.2.46_1.0.36 (1 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-RSA-private-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `usr/sbin/httpsd.pem`
- **Location:** `httpsd.pem`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** A complete RSA private REDACTED_PASSWORD_PLACEHOLDER in PEM format was found in the httpsd.pem file. This private REDACTED_PASSWORD_PLACEHOLDER may be used for encrypted communication or authentication. Multiple related CVE vulnerabilities exist, particularly CVE-2011-4121 (CVSSv3 score: 9.8) and CVE-2020-7352 (CVSSv3 score: 8.4). These vulnerabilities indicate that hardcoded RSA private keys may lead to service integrity compromise or privilege escalation.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  -----END RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  ```
- **Keywords:** httpsd.pem, RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER, PEM, CVE-2011-4121, CVE-2020-7352
- **Notes:** It is recommended to immediately replace this private REDACTED_PASSWORD_PLACEHOLDER and check whether any services are currently using it. Additionally, all services utilizing this private REDACTED_PASSWORD_PLACEHOLDER should be reviewed to ensure there are no security vulnerabilities caused by hardcoded private keys.

---
