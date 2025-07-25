# TL-MR3020_V1_150921 (6 alerts)

---

### shadow-ap71-empty-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow:13`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** The user account ap71 does not have a REDACTED_PASSWORD_PLACEHOLDER set (the second field is empty). This may lead to unauthorized access.
- **Code Snippet:**
  ```
  ap71::...
  ```
- **Keywords:** ap71, empty_password
- **Notes:** The user account not having a REDACTED_PASSWORD_PLACEHOLDER is a serious security issue.

---
### shadow-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Discovered a REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user encrypted using MD5 (identified by the $1$ prefix). The hash value is 'REDACTED_SECRET_KEY_PLACEHOLDER.H3/'. This is a weak encryption method that may be vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:...
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** MD5 hashed passwords can be brute-forced; it is recommended to switch to more secure encryption methods such as SHA-512.

---
### shadow-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow:2`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Discovered that the REDACTED_PASSWORD_PLACEHOLDER user is using the same MD5 encrypted REDACTED_PASSWORD_PLACEHOLDER hash (identified by $1$) as REDACTED_PASSWORD_PLACEHOLDER. The hash value is 'REDACTED_SECRET_KEY_PLACEHOLDER.H3/'. This indicates a potential REDACTED_PASSWORD_PLACEHOLDER reuse issue.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:...
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** Using the same REDACTED_PASSWORD_PLACEHOLDER for REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER users poses security risks.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-privilege

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:2`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A non-REDACTED_PASSWORD_PLACEHOLDER account 'REDACTED_PASSWORD_PLACEHOLDER' with UID 0 was detected, which may pose a privilege escalation risk. This account shares the same UID (0) as the REDACTED_PASSWORD_PLACEHOLDER account and can fully control the system.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:x:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, x:0:0
- **Notes:** Delete or disable this account, or at least change its UID to a non-zero value.

---
### REDACTED_PASSWORD_PLACEHOLDER-ap71-REDACTED_PASSWORD_PLACEHOLDER-privilege

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:13`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** A non-REDACTED_PASSWORD_PLACEHOLDER account 'ap71' with UID 0 was detected, which may pose a privilege escalation risk. This account has REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0) but uses a non-standard REDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  ap71:x:500:0:Linux User,,,:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** ap71, x:500:0
- **Notes:** It is recommended to investigate the purpose of this account; if not necessary, it should be deleted or its UID changed.

---
### default_wsc_cfg-nw_key-template

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER_wsc_cfg.txt`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER_wsc_cfg.txt`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** The commented-out NW_KEY field was discovered, indicating a potential location for hardcoded network keys. Although currently empty, the template shows that a REDACTED_PASSWORD_PLACEHOLDER can be added here.
- **Code Snippet:**
  ```
  # NW_REDACTED_PASSWORD_PLACEHOLDER
  # NW_KEY=REDACTED_PASSWORD_PLACEHOLDER
  NW_KEY=
  ```
- **Keywords:** NW_KEY
- **Notes:** Check other configuration files or runtime behavior to confirm whether NW_KEY is set elsewhere.

---
