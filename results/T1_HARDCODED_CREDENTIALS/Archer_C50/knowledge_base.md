# Archer_C50 (3 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-vsftpd_REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `./etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** The file './etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER' contains multiple hardcoded credentials in plain text format. Each entry follows the pattern 'REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER:flag1:flag2', where the REDACTED_PASSWORD_PLACEHOLDER is stored in cleartext. This poses a significant security risk as anyone with access to this file can obtain valid credentials. The credentials found are:
- REDACTED_PASSWORD_PLACEHOLDER:1234 (privileged account)
- guest:guest (unprivileged account)
- test:test (privileged account)

The presence of flag values (1/0) suggests these may control account privileges (1=privileged, 0=unprivileged).
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** These credentials should be immediately changed or deleted. Consider implementing proper REDACTED_PASSWORD_PLACEHOLDER hashing and moving the credentials to a more secure storage mechanism. Additionally, file permissions should be checked to ensure only authorized users can access them.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.bak:REDACTED_PASSWORD_PLACEHOLDER user entry`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The hardcoded REDACTED_PASSWORD_PLACEHOLDER for the REDACTED_PASSWORD_PLACEHOLDER user was found in the REDACTED_PASSWORD_PLACEHOLDER.bak file, suspected to be encrypted using MD5 ($1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/). This is a high-risk finding, as hardcoded credentials could potentially be exploited by attackers to gain system access.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER.bak, MD5, hardcoded
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER appears to be encrypted using MD5 (with the $1$$ prefix). It is recommended to further analyze the encryption method and check for the presence of a shadow.bak file.

---
### REDACTED_PASSWORD_PLACEHOLDER-propagation-REDACTED_PASSWORD_PLACEHOLDER-copy

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `./etc/init.d/rcS`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The system initialization script copies the sensitive information-containing 'REDACTED_PASSWORD_PLACEHOLDER.bak' file to the '/var/REDACTED_PASSWORD_PLACEHOLDER' location. This may lead to the propagation of hardcoded credentials (including the MD5-encrypted REDACTED_PASSWORD_PLACEHOLDER of the REDACTED_PASSWORD_PLACEHOLDER user) to non-standard locations, increasing the risk of exposure.
- **Code Snippet:**
  ```
  cp REDACTED_PASSWORD_PLACEHOLDER.bak /var/REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, /var/REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, MD5, hardcoded
- **Notes:** Confirmed that 'REDACTED_PASSWORD_PLACEHOLDER.bak' contains hardcoded credentials for the REDACTED_PASSWORD_PLACEHOLDER account. Immediate inspection of '/var/REDACTED_PASSWORD_PLACEHOLDER' is required to determine if identical vulnerabilities exist, along with a security impact assessment of this duplication practice.

---
