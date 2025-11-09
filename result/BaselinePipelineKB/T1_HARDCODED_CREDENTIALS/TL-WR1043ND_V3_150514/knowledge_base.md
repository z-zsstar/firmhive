# TL-WR1043ND_V3_150514 (6 alerts)

---

### default-REDACTED_PASSWORD_PLACEHOLDER-credentials

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** hardcoded_credentials
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** AccessDenied.htm, default REDACTED_PASSWORD_PLACEHOLDER, default REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** hardcoded_credentials

---
### login-authentication

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** authentication_mechanism
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** LoginRpm.htm, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, hex_md5, Base64Encoding, Authorization
- **Notes:** authentication_mechanism

---
### REDACTED_PASSWORD_PLACEHOLDER-shadow-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 10.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER file contains the REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user. This hash is encrypted using the MD5 algorithm (identified by $1$), including the salt (GTN.gpri) and the hash value (REDACTED_PASSWORD_PLACEHOLDER). The REDACTED_PASSWORD_PLACEHOLDER policy is configured as follows: minimum change days 0, maximum validity period 99999 days, and warning period 7 days. This is a standard Unix REDACTED_PASSWORD_PLACEHOLDER hash entry. Although the REDACTED_PASSWORD_PLACEHOLDER is not stored in plaintext, the MD5 algorithm is considered insecure. It is recommended to use more secure hash algorithms such as SHA-512 ($6$) or bcrypt.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER:15502:0:99999:7:::
  ```
- **Keywords:** etc/shadow, REDACTED_PASSWORD_PLACEHOLDER, $1$, GTN.gpri, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** This is a standard Unix REDACTED_PASSWORD_PLACEHOLDER hash entry. Although the REDACTED_PASSWORD_PLACEHOLDER is not stored in plaintext, the MD5 algorithm is considered insecure. It is recommended to use more secure hashing algorithms such as SHA-512($6$) or bcrypt.

---
### wireless-security-configs

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** wireless_credentials
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** WlanSecurityRpm.htm, WEP, PSK, pskSecret, radiusSecret, key1, key2, key3, key4
- **Notes:** wireless_credentials

---
### authentication-logic-exposure

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** REDACTED_PASSWORD_PLACEHOLDER fields and authentication logic found in AutoEmailRpm.htm. The file contains JavaScript code for handling REDACTED_PASSWORD_PLACEHOLDER input, validation, and authentication. This could potentially expose authentication logic to attackers.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** AutoEmailRpm.htm, User, REDACTED_PASSWORD_PLACEHOLDER, VeriPass, Authentication
- **Notes:** authentication_logic

---
### nas-user-management

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** NAS user account management found in NasUserAdvRpm.htm and related files. These files contain functionality for managing NAS user accounts and passwords.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** NasUserAdvRpm.htm, nas_REDACTED_PASSWORD_PLACEHOLDER, nas_REDACTED_PASSWORD_PLACEHOLDER, nas_admin_confirm_pwd
- **Notes:** NAS access controls are important for data security. These implementations should be reviewed.

---
