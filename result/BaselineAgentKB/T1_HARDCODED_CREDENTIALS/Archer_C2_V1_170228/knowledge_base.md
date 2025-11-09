# Archer_C2_V1_170228 (1 alerts)

---

### hardcoded-credentials-REDACTED_PASSWORD_PLACEHOLDER.bak

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Hardcoded user credentials were found in the REDACTED_PASSWORD_PLACEHOLDER.bak file. The REDACTED_PASSWORD_PLACEHOLDER for the REDACTED_PASSWORD_PLACEHOLDER user is stored using MD5 encryption, which can be cracked. This poses a serious security risk that could lead to unauthorized access.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER.bak, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER is hashed using MD5 encryption, which has low security. It is recommended to change the REDACTED_PASSWORD_PLACEHOLDER immediately.

---
