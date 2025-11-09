# TL-MR3020_V1_150921 (2 alerts)

---

### auth-multiple-REDACTED_PASSWORD_PLACEHOLDER-accounts

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:1,2 etc/shadow:1,2`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** The system has two accounts with REDACTED_PASSWORD_PLACEHOLDER privileges (REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER), both using the same weak MD5 REDACTED_PASSWORD_PLACEHOLDER hash ($1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/). This allows attackers to gain access to both accounts by cracking one REDACTED_PASSWORD_PLACEHOLDER. The MD5 hashing algorithm is known to be insecure and vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER:x:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, $1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** It is recommended to enforce REDACTED_PASSWORD_PLACEHOLDER changes and use a stronger hashing algorithm (such as SHA-512).

---
### auth-empty-passwords

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:3-13 etc/shadow:3-13`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** Multiple system accounts (bin, daemon, adm, lp, sync, shutdown, halt, uucp, operator, nobody, ap71) have no REDACTED_PASSWORD_PLACEHOLDER set or have empty REDACTED_PASSWORD_PLACEHOLDER fields. This allows potential attackers to gain system access without requiring a REDACTED_PASSWORD_PLACEHOLDER. Notably, the ap71 account has REDACTED_PASSWORD_PLACEHOLDER privileges (UID 500) but lacks a REDACTED_PASSWORD_PLACEHOLDER setting.
- **Code Snippet:**
  ```
  bin::10933:0:99999:7:::
  daemon::10933:0:99999:7:::
  adm::10933:0:99999:7:::
  ap71::10933:0:99999:7:::
  ```
- **Keywords:** bin, daemon, adm, lp, sync, shutdown, halt, uucp, operator, nobody, ap71
- **Notes:** It is recommended to set strong passwords for all system accounts, especially for privileged accounts.

---
