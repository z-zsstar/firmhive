# TL-MR3020_V1_150921 (3 alerts)

---

### hardcoded-credentials-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1-2`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** It was discovered that the REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER users share the same MD5-encrypted REDACTED_PASSWORD_PLACEHOLDER hash. This indicates a default REDACTED_PASSWORD_PLACEHOLDER risk, and the administrator account employs weak encryption. The hash value is susceptible to offline cracking.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, $1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** The MD5 hashing algorithm has been proven insecure; it is recommended to use more robust hashing algorithms such as SHA-512.

---
### hardcoded-3g-credentials

- **File/Directory Path:** `N/A`
- **Location:** `etc/3gISP/ISP0:3-4`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Hardcoded APN credentials were found in the 3G ISP configuration file, including the REDACTED_PASSWORD_PLACEHOLDER (ctnet@mycdma.cn) and REDACTED_PASSWORD_PLACEHOLDER (vnet.mobi). These credentials may be used for devices to connect to the 3G network.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER=ctnet@mycdma.cn
  REDACTED_PASSWORD_PLACEHOLDER=vnet.mobi
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER=ctnet@mycdma.cn, REDACTED_PASSWORD_PLACEHOLDER=vnet.mobi, APN, 3G
- **Notes:** These credentials may be specific to China Telecom's network services.

---
### empty-REDACTED_PASSWORD_PLACEHOLDER-accounts

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:3-13`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Multiple system accounts (ap71, bin, daemon, etc.) were found without REDACTED_PASSWORD_PLACEHOLDER protection or with empty REDACTED_PASSWORD_PLACEHOLDER fields, which may lead to unauthorized access.
- **Code Snippet:**
  ```
  ap71::10933:0:99999:7:::
  bin::10933:0:99999:7:::
  ```
- **Keywords:** ap71, bin, daemon, nobody
- **Notes:** Accounts with empty passwords may be exploited for privilege escalation attacks.

---
