# FH1201 (6 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-privilege-assignment-etc-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:1-4`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** All users (REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody) have their UID and GID set to 0 (REDACTED_PASSWORD_PLACEHOLDER privileges), which is a critical security risk. Any user can gain full REDACTED_PASSWORD_PLACEHOLDER access.
- **Keywords:** 0:0
- **Notes:** These users' UID/GID should be immediately modified to non-zero values, adhering to the principle of least privilege.

---
### MD5-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-etc-shadow_private

- **File/Directory Path:** `etc/shadow_private`
- **Location:** `etc/shadow_private:1`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** An MD5 encrypted REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user was found in the REDACTED_PASSWORD_PLACEHOLDER_private file. This hash uses the MD5 encryption algorithm (identified by $1$). If exposed, this storage method could allow attackers to perform offline brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Recommendations: 1) If this is a production system, the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER should be changed immediately 2) Check whether other services are using the same REDACTED_PASSWORD_PLACEHOLDER 3) Consider using more secure hash algorithms such as SHA-512 ($6$)

---
### FTP-anonymous-access-etc-stupid-ftpd

- **File/Directory Path:** `etc/stupid-ftpd/stupid-ftpd.conf`
- **Location:** `etc/stupid-ftpd/stupid-ftpd.conf: HIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 10.0
- **Description:** Hardcoded FTP user credentials, including REDACTED_PASSWORD_PLACEHOLDER and permission configurations, were found in the stupid-ftpd.conf file. Anonymous access is configured with full permissions (A), which may pose a security risk.
- **Code Snippet:**
  ```
  user=anonymous	*	 /	  5   A
  ```
- **Keywords:** user=anonymous, *, A
- **Notes:** The anonymous user is granted full permissions (A), which may lead to unauthorized access. It is recommended to restrict anonymous user permissions or disable anonymous access.

---
### DES-encrypted-REDACTED_PASSWORD_PLACEHOLDER-etc-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:1-4`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** DES-encrypted user passwords were found in the REDACTED_PASSWORD_PLACEHOLDER file. Although encrypted, they still constitute sensitive REDACTED_PASSWORD_PLACEHOLDER information. The passwords are stored in the REDACTED_PASSWORD_PLACEHOLDER file instead of the more secure REDACTED_PASSWORD_PLACEHOLDER file. Attackers could use REDACTED_PASSWORD_PLACEHOLDER cracking tools (such as John the Ripper) to attempt to crack these hashes.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody
- **Notes:** It is recommended to migrate these REDACTED_PASSWORD_PLACEHOLDER hashes to the REDACTED_PASSWORD_PLACEHOLDER file and set appropriate file permissions. Consider enforcing REDACTED_PASSWORD_PLACEHOLDER policy updates.

---
### MD5-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-etc-shadow

- **File/Directory Path:** `etc/shadow`
- **Location:** `etc/shadow:1`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The MD5 encrypted REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user was found in the REDACTED_PASSWORD_PLACEHOLDER file. This hash uses the MD5 encryption algorithm (identified by $1$). If exposed, this storage method could allow attackers to perform offline brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to change the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER to a stronger one and ensure it is not reused in other systems.

---
### real-chroot-config-etc-stupid-ftpd

- **File/Directory Path:** `etc/stupid-ftpd/stupid-ftpd.conf`
- **Location:** `etc/stupid-ftpd/stupid-ftpd.conf: HIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** The server is configured to use a real chroot (requiring REDACTED_PASSWORD_PLACEHOLDER privileges), combined with an anonymous user having full permissions, which may increase system risks.
- **Code Snippet:**
  ```
  changeroottype=real
  REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** changeroottype=real, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** A real chroot configuration requires REDACTED_PASSWORD_PLACEHOLDER privileges, and combining it with an anonymous user having full permissions may pose a privilege escalation risk.

---
