# FH1201 (5 alerts)

---

### privilege-user-root_equivalent_accounts

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:1-4`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Hardcoded credentials for privileged users (UID 0) were identified, including REDACTED_PASSWORD_PLACEHOLDER and support accounts. These accounts possess REDACTED_PASSWORD_PLACEHOLDER privileges, which could lead to complete system compromise if passwords are cracked. Privileged accounts should implement stricter access controls and multi-factor authentication.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER:0, support:0, user:0, nobody:0
- **Notes:** 4 privileged accounts with UID 0 detected: REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody. These accounts possess REDACTED_PASSWORD_PLACEHOLDER privileges, posing critical security risks.

---
### REDACTED_PASSWORD_PLACEHOLDER-unix_password-root_md5_hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 10.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user has been discovered. This hash is encrypted using the MD5 algorithm (identified by $1$). The hash value can be cracked by offline tools. REDACTED_PASSWORD_PLACEHOLDER hash type: MD5 ($1$). Recommendations: 1) This hash should be replaced with a more secure algorithm such as SHA-512 ($6$); 2) If the system permits, REDACTED_PASSWORD_PLACEHOLDER-based REDACTED_PASSWORD_PLACEHOLDER login should be disabled in favor of REDACTED_PASSWORD_PLACEHOLDER-based authentication.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, OVhtCyFa, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER type: UNIX REDACTED_PASSWORD_PLACEHOLDER hash (MD5 crypt). Original value: $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER. MD5 hash cannot be directly decoded (one-way encryption), but plaintext can be recovered through brute-force cracking.

---
### REDACTED_PASSWORD_PLACEHOLDER-unix_password-root_md5_hash_shadow_private

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow_private:1`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** A hardcoded REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user was detected. This hash is encrypted using MD5 (identified by the $1$ prefix) and stored in the shadow file format. This storage method poses a security risk, as MD5 hashes are vulnerable to brute-force attacks. Recommendations: 1) Replace this REDACTED_PASSWORD_PLACEHOLDER hash with a more secure encryption method (e.g., SHA-512); 2) Consider using a randomly generated strong REDACTED_PASSWORD_PLACEHOLDER; 3) Verify whether the same REDACTED_PASSWORD_PLACEHOLDER is used elsewhere in the system.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER, shadow_private
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER type: UNIX REDACTED_PASSWORD_PLACEHOLDER hash (MD5). Original value: $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER. MD5 hashes are considered insecure and can be rapidly cracked by modern hardware.

---
### REDACTED_PASSWORD_PLACEHOLDER-unix_password-root_md5_REDACTED_PASSWORD_PLACEHOLDER_private

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER_private:1`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Hardcoded REDACTED_PASSWORD_PLACEHOLDER credentials were found in the `etc/REDACTED_PASSWORD_PLACEHOLDER_private` file. The REDACTED_PASSWORD_PLACEHOLDER is stored using MD5 encryption (indicated by the $1$ prefix). This storage method poses a security risk as MD5 encryption is vulnerable to cracking. If attackers obtain this file, they could attempt brute-force attacks to crack the REDACTED_PASSWORD_PLACEHOLDER. Recommendations: 1) Delete or secure this file 2) Change the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER 3) Consider adopting more secure REDACTED_PASSWORD_PLACEHOLDER hashing algorithms such as SHA-256 or bcrypt.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER_private, REDACTED_PASSWORD_PLACEHOLDER, $1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER type: UNIX user REDACTED_PASSWORD_PLACEHOLDER (MD5 encrypted). Hash value: $1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1. This is a newly discovered REDACTED_PASSWORD_PLACEHOLDER hash, different from the previously found REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER.

---
### REDACTED_PASSWORD_PLACEHOLDER-unix_password-REDACTED_PASSWORD_PLACEHOLDER_des_hashes

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER:1-4`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** Hardcoded user REDACTED_PASSWORD_PLACEHOLDER credentials were discovered, stored in DES encryption format. Each entry includes the REDACTED_PASSWORD_PLACEHOLDER, encrypted REDACTED_PASSWORD_PLACEHOLDER, user ID, group ID, user description, home directory, and default shell. This information could be exploited for brute-force attacks or REDACTED_PASSWORD_PLACEHOLDER recovery attempts. DES-encrypted passwords can be cracked using tools such as John the Ripper or hashcat. It is recommended to adopt more secure REDACTED_PASSWORD_PLACEHOLDER storage mechanisms like shadow files and stronger hashing algorithms.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody, 6HgsSsJIEOc2U, Ead09Ca6IhzZY, tGqcT.qjxbEik, VBcCXSNG7zBAY
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER type: UNIX REDACTED_PASSWORD_PLACEHOLDER hash (DES crypt). Original values: 6HgsSsJIEOc2U(REDACTED_PASSWORD_PLACEHOLDER), Ead09Ca6IhzZY(support), tGqcT.qjxbEik(user), VBcCXSNG7zBAY(nobody). DES encryption can be cracked by cracking tools.

---
