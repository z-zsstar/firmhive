# _US_AC18V1.0BR_V15.03.05.05_multi_TD01.bin.extracted (8 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-shadow-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `./etc_ro/shadow`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** The encrypted REDACTED_PASSWORD_PLACEHOLDER for the REDACTED_PASSWORD_PLACEHOLDER user was found in the shadow file. The REDACTED_PASSWORD_PLACEHOLDER is encrypted using the DES algorithm (prefix $1$). The REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER is the highest-privilege REDACTED_PASSWORD_PLACEHOLDER in the system.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** shadow, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER is the highest privilege REDACTED_PASSWORD_PLACEHOLDER of the system and requires special attention. The REDACTED_PASSWORD_PLACEHOLDER type is user REDACTED_PASSWORD_PLACEHOLDER.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-users

- **File/Directory Path:** `N/A`
- **Location:** `./etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Multiple user accounts and encrypted passwords were found in the REDACTED_PASSWORD_PLACEHOLDER file. The passwords are encrypted using the DES algorithm (prefixed with $1$). These credentials could potentially be used for system access. Accounts include REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody, among others.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody
- **Notes:** It is recommended to conduct cracking tests or forced modifications on these passwords. The REDACTED_PASSWORD_PLACEHOLDER type is user REDACTED_PASSWORD_PLACEHOLDER.

---
### samba-insecure-config

- **File/Directory Path:** `N/A`
- **Location:** `./etc_ro/smb.conf`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Insecure Samba service configuration detected in smb.conf: REDACTED_PASSWORD_PLACEHOLDER user account is being used with null passwords enabled (null passwords = yes), posing critical security risks by allowing unauthenticated access.
- **Keywords:** valid users = REDACTED_PASSWORD_PLACEHOLDER, null passwords = yes
- **Notes:** Disable empty passwords and enforce strong passwords, restrict the list of valid users

---
### shadow-REDACTED_PASSWORD_PLACEHOLDER-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user was found in the shadow file, encrypted using the MD5 algorithm. This could potentially allow attackers to gain REDACTED_PASSWORD_PLACEHOLDER access through brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, shadow
- **Notes:** It is recommended to immediately change the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER and use a more secure hashing algorithm

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-credentials

- **File/Directory Path:** `N/A`
- **Location:** `./etc_ro/REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Hardcoded credentials were found in /etc_ro/REDACTED_PASSWORD_PLACEHOLDER, containing two users: REDACTED_PASSWORD_PLACEHOLDER and user, with REDACTED_PASSWORD_PLACEHOLDER hashes encrypted using DES. DES encryption is vulnerable to brute-force attacks, especially when weak passwords are used.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U, user:tGqcT.qjxbEik
- **Notes:** It is recommended to change these default credentials immediately and use more secure encryption algorithms such as SHA-512.

---
### nginx-REDACTED_PASSWORD_PLACEHOLDER-privilege

- **File/Directory Path:** `N/A`
- **Location:** `./etc_ro/nginx/conf/nginx.conf:1`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** The nginx configuration runs with REDACTED_PASSWORD_PLACEHOLDER user privileges (worker processes), which expands the potential attack surface. Once the service is compromised, it will gain REDACTED_PASSWORD_PLACEHOLDER access.
- **Keywords:** user REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** privilege_issue

---
### acsd-potential-credentials

- **File/Directory Path:** `N/A`
- **Location:** `usr/sbin/acsd`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Two potential hardcoded REDACTED_PASSWORD_PLACEHOLDER strings were identified in the acsd binary. These strings exhibit characteristics of passwords or keys, but lack explicit contextual information regarding their purpose. The first string was found near functions related to wireless networking, while the second string appeared in proximity to channel selection logic.
- **Keywords:** Ygs12Fail,gth234@!2, YUs12dfsKM,g54qweref@31, td_acs_run_scan_mark, td_acs_select_chspec_normal_func
- **Notes:** Further verification is needed to determine the actual purpose of these strings. They may be test credentials, default passwords, or internal authentication keys.

---
### smb-null-passwords

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/smb.conf:12,13`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The configuration in the smb.conf file allows null passwords (null passwords = yes) and REDACTED_PASSWORD_PLACEHOLDER encryption (encrypt passwords = yes), which may reduce system security.
- **Code Snippet:**
  ```
  encrypt passwords = yes
  null passwords = yes
  ```
- **Keywords:** null passwords, encrypt passwords, smb.conf
- **Notes:** It is recommended to disable the empty REDACTED_PASSWORD_PLACEHOLDER option.

---
