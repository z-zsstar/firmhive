# Archer_C2_V1_170228 (2 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** A hardcoded REDACTED_PASSWORD_PLACEHOLDER hash (MD5 crypt format) for the 'REDACTED_PASSWORD_PLACEHOLDER' user was discovered in the 'etc/REDACTED_PASSWORD_PLACEHOLDER.bak' file. This file is copied to '/var/REDACTED_PASSWORD_PLACEHOLDER' during system startup (controlled by commands in etc/init.d/rcS), creating a complete REDACTED_PASSWORD_PLACEHOLDER propagation path. Hash value: $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/, cp
- **Notes:** Full REDACTED_PASSWORD_PLACEHOLDER propagation path: 1) Hardcoded in REDACTED_PASSWORD_PLACEHOLDER.bak 2) Copied to runtime location via rcS script. Recommend checking if the system uses this REDACTED_PASSWORD_PLACEHOLDER for authentication.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** A hardcoded REDACTED_PASSWORD_PLACEHOLDER hash for the 'REDACTED_PASSWORD_PLACEHOLDER' user was found in the 'etc/REDACTED_PASSWORD_PLACEHOLDER.bak' file. The REDACTED_PASSWORD_PLACEHOLDER is stored in MD5 crypt format (prefixed with $1$), posing a security risk as the hash could be cracked offline. The hash value is: $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** The file also contains configurations for standard system accounts (dropbear and nobody), with no other sensitive information found.

---
