# TL-WA701ND_V2_140324 (6 alerts)

---

### shadow-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 9.5
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER user's REDACTED_PASSWORD_PLACEHOLDER in the REDACTED_PASSWORD_PLACEHOLDER file is encrypted using MD5 (identified by $1$). This REDACTED_PASSWORD_PLACEHOLDER hash may be vulnerable to brute-force attacks. The REDACTED_PASSWORD_PLACEHOLDER field follows the Unix crypt(3) standard format and employs the MD5 algorithm.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** UNIX REDACTED_PASSWORD_PLACEHOLDER hash (MD5)

---
### REDACTED_PASSWORD_PLACEHOLDER-ap71-account

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:13`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** A non-REDACTED_PASSWORD_PLACEHOLDER account 'ap71' with UID 0 was found in the REDACTED_PASSWORD_PLACEHOLDER file, which may allow privilege escalation. This account has UID 500 but GID 0, with the home directory set to /REDACTED_PASSWORD_PLACEHOLDER.
- **Keywords:** ap71, x:500:0
- **Notes:** This account is configured abnormally, with a GID of 0 granting it REDACTED_PASSWORD_PLACEHOLDER group privileges. It is recommended to investigate and remove this account.

---
### shadow-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow:2`
- **Risk Score:** 8.0
- **Confidence:** 9.25
- **Description:** UNIX REDACTED_PASSWORD_PLACEHOLDER hash (MD5)  

The REDACTED_PASSWORD_PLACEHOLDER file reveals that the REDACTED_PASSWORD_PLACEHOLDER user has set the same MD5-encrypted REDACTED_PASSWORD_PLACEHOLDER as REDACTED_PASSWORD_PLACEHOLDER. This indicates a REDACTED_PASSWORD_PLACEHOLDER reuse risk, potentially allowing for horizontal privilege escalation.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** Using the same REDACTED_PASSWORD_PLACEHOLDER for REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER accounts is a serious security risk.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-account

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:2`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A non-REDACTED_PASSWORD_PLACEHOLDER account 'REDACTED_PASSWORD_PLACEHOLDER' with UID 0 was found in the REDACTED_PASSWORD_PLACEHOLDER file, which could allow privilege escalation. This account shares the same UID (0) as the REDACTED_PASSWORD_PLACEHOLDER account and has its home directory set to /REDACTED_PASSWORD_PLACEHOLDER.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, x:0:0
- **Notes:** Any user who knows the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER can obtain REDACTED_PASSWORD_PLACEHOLDER privileges. It is recommended to delete or disable this account.

---
### shadow-empty-passwords

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow:3-13`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** Multiple system accounts (such as bin, daemon, etc.) in the REDACTED_PASSWORD_PLACEHOLDER file were found to have empty REDACTED_PASSWORD_PLACEHOLDER fields, posing a security risk. Empty REDACTED_PASSWORD_PLACEHOLDER fields indicate that these accounts can be logged into without requiring a REDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  bin::10933:0:99999:7:::
  ```
- **Keywords:** bin, daemon, adm, nobody, ap71
- **Notes:** System accounts with empty passwords should be locked or set with strong passwords.

---
### bpalogin-config-path

- **File/Directory Path:** `usr/sbin/bpalogin`
- **Location:** `usr/sbin/bpalogin:0x00005acc`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** The configuration file path 'REDACTED_PASSWORD_PLACEHOLDER.conf' was found in usr/sbin/bpalogin, which may contain sensitive authentication information.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.conf
- **Notes:** Configuration file reference

---
