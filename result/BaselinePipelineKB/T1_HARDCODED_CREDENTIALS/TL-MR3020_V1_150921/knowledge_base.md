# TL-MR3020_V1_150921 (4 alerts)

---

### privilege-ap71-uid0

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:13`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Discovered a non-REDACTED_PASSWORD_PLACEHOLDER account 'ap71' with UID 0, which may pose privilege escalation risks. This account possesses REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0) while using a regular REDACTED_PASSWORD_PLACEHOLDER, potentially serving as a covert backdoor access.
- **Code Snippet:**
  ```
  ap71:x:500:0:Linux User,,,:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** ap71, x:500:0
- **Notes:** The home directory of this account is set to /REDACTED_PASSWORD_PLACEHOLDER instead of /home/ap71, further increasing suspicion. It is recommended to investigate this account immediately.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-weak-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER user has been found to have a weak REDACTED_PASSWORD_PLACEHOLDER hash. This hash uses the MD5 algorithm (indicated by the $1$ prefix) and is identical to the REDACTED_PASSWORD_PLACEHOLDER user's REDACTED_PASSWORD_PLACEHOLDER. This indicates a REDACTED_PASSWORD_PLACEHOLDER reuse risk within the system. The hash value is vulnerable to brute-force attacks or rainbow table attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** It is recommended to enforce changing the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER to a strong REDACTED_PASSWORD_PLACEHOLDER, and it should not be shared with other accounts.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-reused-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:2`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER user was found to have set the same MD5 hash REDACTED_PASSWORD_PLACEHOLDER as REDACTED_PASSWORD_PLACEHOLDER. This REDACTED_PASSWORD_PLACEHOLDER reuse behavior significantly increases the risk of lateral movement. Attackers can gain access to two privileged accounts by compromising just one.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** Implement the principle of least privilege and assign unique strong passwords to different accounts.

---
### privilege-REDACTED_PASSWORD_PLACEHOLDER-uid0

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:2`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** Discovered a non-REDACTED_PASSWORD_PLACEHOLDER account 'REDACTED_PASSWORD_PLACEHOLDER' with UID 0, which may pose a privilege escalation risk. This account shares the same UID (0) as the REDACTED_PASSWORD_PLACEHOLDER account but uses a different REDACTED_PASSWORD_PLACEHOLDER, potentially serving as a covert backdoor access.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:x:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, x:0:0
- **Notes:** It is recommended to check whether there is a legitimate user named 'REDACTED_PASSWORD_PLACEHOLDER' in the system. If not, this account should be deleted immediately.

---
