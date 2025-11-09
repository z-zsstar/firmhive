# Archer_C2_V1_170228 (1 alerts)

---

### configuration_load-REDACTED_PASSWORD_PLACEHOLDER.bak-user_credentials

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Three user accounts were found in the 'etc/REDACTED_PASSWORD_PLACEHOLDER.bak' file: REDACTED_PASSWORD_PLACEHOLDER, dropbear, and nobody. The REDACTED_PASSWORD_PLACEHOLDER field for the REDACTED_PASSWORD_PLACEHOLDER user contains the encrypted hash '$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/', which may pose a security risk as the hash could be cracked. The REDACTED_PASSWORD_PLACEHOLDER field for the dropbear user is 'x', indicating that the REDACTED_PASSWORD_PLACEHOLDER is stored in the shadow file. The REDACTED_PASSWORD_PLACEHOLDER field for the nobody user is '*', indicating that the account is disabled.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  dropbear:x:500:500:dropbear:/var/dropbear:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, dropbear, nobody, user_credentials, password_hash
- **Notes:** It is recommended to further inspect the shadow file for additional REDACTED_PASSWORD_PLACEHOLDER information and assess whether the REDACTED_PASSWORD_PLACEHOLDER user's hash is susceptible to being cracked.

---
