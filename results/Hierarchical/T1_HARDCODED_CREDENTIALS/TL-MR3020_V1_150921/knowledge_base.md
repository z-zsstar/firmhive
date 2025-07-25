# TL-MR3020_V1_150921 (2 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-shadow

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The 'etc/shadow' file contains encrypted passwords for the 'REDACTED_PASSWORD_PLACEHOLDER' and 'REDACTED_PASSWORD_PLACEHOLDER' accounts, stored as MD5 hashes (indicated by $1$ prefix). MD5 is a weak hashing algorithm, making these credentials potentially vulnerable to cracking. Other accounts are either REDACTED_PASSWORD_PLACEHOLDER-less or locked (indicated by *).
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, MD5, shadow
- **Notes:** configuration_load

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-accounts

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** The 'REDACTED_PASSWORD_PLACEHOLDER' file contains user account information with encrypted passwords (indicated by 'x'). The file includes standard system accounts and two notable accounts with REDACTED_PASSWORD_PLACEHOLDER privileges: 'REDACTED_PASSWORD_PLACEHOLDER' and 'ap71'. The presence of these accounts could pose a security risk if their passwords are weak or default. The encrypted passwords are stored in the 'shadow' file, which should be analyzed next for potential weak or default passwords.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER:x:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ap71:x:500:0:Linux User,,,:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, ap71, x
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER

---
