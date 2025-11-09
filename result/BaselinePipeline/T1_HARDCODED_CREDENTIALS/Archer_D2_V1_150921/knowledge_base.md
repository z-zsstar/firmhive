# Archer_D2_V1_150921 (2 alerts)

---

### vsftpd-REDACTED_PASSWORD_PLACEHOLDER-credentials

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** Plaintext FTP credentials were found in the vsftpd_REDACTED_PASSWORD_PLACEHOLDER file, including the REDACTED_PASSWORD_PLACEHOLDER user using the simple REDACTED_PASSWORD_PLACEHOLDER '1234', as well as guest and test users employing their REDACTED_PASSWORD_PLACEHOLDERs as passwords. These weak passwords are vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** All passwords are stored in plaintext, without encryption or hashing. It is recommended to change these credentials immediately and implement a secure REDACTED_PASSWORD_PLACEHOLDER storage mechanism.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-credentials

- **File/Directory Path:** `.REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Hardcoded credentials for the REDACTED_PASSWORD_PLACEHOLDER user were found in the REDACTED_PASSWORD_PLACEHOLDER.bak file. This account has REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0), with the REDACTED_PASSWORD_PLACEHOLDER encrypted using weak MD5 hashing (indicated by $1$ prefix), showing the hash value $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/. This vulnerable encryption method is easily crackable, posing critical security risks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/, REDACTED_PASSWORD_PLACEHOLDER.bak
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER uses weak encryption (MD5), it is recommended to change these credentials immediately.

---
