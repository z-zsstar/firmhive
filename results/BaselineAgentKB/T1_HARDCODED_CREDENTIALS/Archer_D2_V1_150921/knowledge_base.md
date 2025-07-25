# Archer_D2_V1_150921 (2 alerts)

---

### hardcoded-credentials-vsftpd-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `./etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The vsftpd_REDACTED_PASSWORD_PLACEHOLDER file contains plaintext FTP credentials: the REDACTED_PASSWORD_PLACEHOLDER for the REDACTED_PASSWORD_PLACEHOLDER user is 1234, and the REDACTED_PASSWORD_PLACEHOLDER for the guest user is guest. These weak passwords are vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest
- **Notes:** These credentials should be changed immediately.

---
### hardcoded-credentials-REDACTED_PASSWORD_PLACEHOLDER-bak

- **File/Directory Path:** `N/A`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** An encrypted REDACTED_PASSWORD_PLACEHOLDER (hash) for the REDACTED_PASSWORD_PLACEHOLDER user was found in the REDACTED_PASSWORD_PLACEHOLDER.bak file. This file is a backup of REDACTED_PASSWORD_PLACEHOLDER and contains system user authentication information. The hash type is MD5 ($1$), which can be cracked.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** configuration_load

---
