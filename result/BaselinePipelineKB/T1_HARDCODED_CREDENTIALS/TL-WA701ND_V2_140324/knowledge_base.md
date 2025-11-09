# TL-WA701ND_V2_140324 (5 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-ap71-empty-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:13`
- **Risk Score:** 9.0
- **Confidence:** 9.75
- **Description:** The ap71 user account REDACTED_PASSWORD_PLACEHOLDER field is found to be empty, allowing REDACTED_PASSWORD_PLACEHOLDER-less login, which poses a serious security risk.
- **Code Snippet:**
  ```
  ap71::10933:0:99999:7:::
  ```
- **Keywords:** ap71, empty_password
- **Notes:** Set a REDACTED_PASSWORD_PLACEHOLDER immediately or disable this account

---
### privilege-ap71-REDACTED_PASSWORD_PLACEHOLDER-uid

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:13`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** A non-REDACTED_PASSWORD_PLACEHOLDER user 'ap71' with UID 0 was detected, which may pose a privilege escalation risk. This user has superuser privileges (UID 0) and its home directory is set to /REDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  ap71:x:500:0:Linux User,,,:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** ap71, x:500:0
- **Notes:** This is a critical security vulnerability where attackers could potentially gain REDACTED_PASSWORD_PLACEHOLDER privileges directly through this account. Immediate investigation and remediation are required.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-weak-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER user has been found to have a weak REDACTED_PASSWORD_PLACEHOLDER hash. The hash format is MD5($1$), and it is identical to the REDACTED_PASSWORD_PLACEHOLDER user's hash, indicating REDACTED_PASSWORD_PLACEHOLDER reuse. This hash can be cracked by brute-force tools.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** It is recommended to enforce changing the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER and use a stronger encryption algorithm (such as SHA-512).

---
### privilege-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-uid

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:2`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A non-REDACTED_PASSWORD_PLACEHOLDER user 'REDACTED_PASSWORD_PLACEHOLDER' with UID 0 was detected, which may lead to privilege escalation risks. This user shares the same UID (0) as the REDACTED_PASSWORD_PLACEHOLDER user, meaning it possesses superuser privileges. Attackers could potentially exploit this account for privilege escalation.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:x:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, x:0:0
- **Notes:** It is recommended to check whether this account exists in the system and confirm its necessity. If it is not necessary, the account should be deleted or its UID modified.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-weak-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:2`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER user was found to have set the same weak REDACTED_PASSWORD_PLACEHOLDER hash as REDACTED_PASSWORD_PLACEHOLDER, posing a privilege escalation risk.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** It is recommended to delete or disable the REDACTED_PASSWORD_PLACEHOLDER account, or set an independent strong REDACTED_PASSWORD_PLACEHOLDER.

---
