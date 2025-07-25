# TD-W8980_V1_150514 (15 alerts)

---

### credentials-ftp-REDACTED_PASSWORD_PLACEHOLDER-1234

- **File/Directory Path:** `N/A`
- **Location:** `./etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 5.0
- **Description:** Discovered hardcoded FTP credentials 'REDACTED_PASSWORD_PLACEHOLDER:1234' for the REDACTED_PASSWORD_PLACEHOLDER user, stored in plaintext, posing a critical security risk. Attackers could directly obtain these credentials for unauthorized access.
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234
- **Notes:** It is recommended to change the REDACTED_PASSWORD_PLACEHOLDER immediately and adopt a secure REDACTED_PASSWORD_PLACEHOLDER storage mechanism

---
### credentials-ftp-guest-guest

- **File/Directory Path:** `N/A`
- **Location:** `./etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 5.0
- **Description:** Hardcoded FTP credentials 'guest:guest' were discovered for the guest user, stored in plaintext, posing a critical security risk. This weak REDACTED_PASSWORD_PLACEHOLDER is highly vulnerable to brute-force attacks.
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, guest:guest
- **Notes:** It is recommended to disable or strengthen the authentication of the guest account.

---
### credentials-ftp-test-test

- **File/Directory Path:** `N/A`
- **Location:** `./etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 5.0
- **Description:** Discovered hardcoded FTP credentials 'test:test' for the test user, stored in plaintext, posing a critical security risk. Such test accounts are often overlooked but may possess elevated privileges.
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, test:test
- **Notes:** Delete test accounts or change to strong passwords

---
### credentials-hardcoded-REDACTED_PASSWORD_PLACEHOLDER-1234

- **File/Directory Path:** `N/A`
- **Location:** `strings output (approx line 500)`
- **Risk Score:** 9.5
- **Confidence:** 4.5
- **Description:** Hardcoded test credentials 'REDACTED_PASSWORD_PLACEHOLDER:1234' were discovered, representing a clear security risk that could potentially allow attackers to gain unauthorized access.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, 1234
- **Notes:** It is recommended to immediately change these credentials and review all authentication mechanisms

---
### credentials-FTP-vsftpd_REDACTED_PASSWORD_PLACEHOLDER_admin

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** Hardcoded FTP credentials found, REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER 1234, stored in plaintext with no encoding traces detected. These credentials may be used for vsftpd service authentication. The meaning of flag field 1:1 requires further analysis.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER is stored in plaintext; it is recommended to change these default credentials immediately. The flag field 1:1 may indicate account permissions or status.

---
### credentials-FTP-vsftpd_REDACTED_PASSWORD_PLACEHOLDER_guest

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** Hardcoded FTP credentials found with REDACTED_PASSWORD_PLACEHOLDER "guest" and REDACTED_PASSWORD_PLACEHOLDER "guest", stored in plaintext without any encoding traces. These credentials may be used for authentication with the vsftpd service. The meaning of the flag field 0:0 requires further analysis.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, guest:guest
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER is stored in plaintext; it is recommended to immediately change these default credentials. The flag field 0:0 may indicate account permissions or status.

---
### credentials-FTP-vsftpd_REDACTED_PASSWORD_PLACEHOLDER_test

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** Hardcoded FTP credentials were found with the REDACTED_PASSWORD_PLACEHOLDER 'test' and REDACTED_PASSWORD_PLACEHOLDER 'test', stored in plaintext with no signs of encoding. These credentials may be used for authentication with the vsftpd service. The meaning of the flag field 1:1 requires further analysis.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, test:test
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER is stored in plaintext; it is recommended to change these default credentials immediately. The flag field 1:1 may indicate account permissions or status.

---
### credentials-user-REDACTED_PASSWORD_PLACEHOLDER-md5-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The MD5 REDACTED_PASSWORD_PLACEHOLDER hash (starting with $1$) of the REDACTED_PASSWORD_PLACEHOLDER user was discovered. This type of hash is vulnerable to brute-force attacks or rainbow table attacks. The account has REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0).
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** MD5 hash values can be cracked offline. It is recommended to delete or disable this account, or change the REDACTED_PASSWORD_PLACEHOLDER to a more secure hashing algorithm.

---
### sensitive-paths-vsftpd-email-passwords

- **File/Directory Path:** `N/A`
- **Location:** `strings output (multiple locations)`
- **Risk Score:** 8.0
- **Confidence:** 4.0
- **Description:** Multiple configuration file paths have been detected, including the REDACTED_PASSWORD_PLACEHOLDER file path 'REDACTED_PASSWORD_PLACEHOLDER.email_passwords', which may contain sensitive information.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.email_passwords, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Check if these files exist and review their contents

---
### vulnerable-version-vsftpd-2.3.2

- **File/Directory Path:** `N/A`
- **Location:** `strings output`
- **Risk Score:** 7.5
- **Confidence:** 4.5
- **Description:** Discovered FTP service version information 'vsftpd: version 2.3.2', which may contain known vulnerabilities.
- **Keywords:** vsftpd: version 2.3.2
- **Notes:** It is recommended to check the security advisories for this version and consider upgrading.

---
### hardcoded-paths-upnp

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/upnpd (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 4.75
- **Description:** Hardcoded file paths detected, including configuration file paths and database paths. Attackers may exploit these paths for information gathering or attacks.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.conf, /var/tmp/upnpd/pm.db, /var/vsftp/var/port
- **Notes:** These paths may contain sensitive configuration information or port mapping data.

---
### REDACTED_PASSWORD_PLACEHOLDER-ldap-REDACTED_PASSWORD_PLACEHOLDER-option

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/REDACTED_PASSWORD_PLACEHOLDER .rodata section`
- **Risk Score:** 7.0
- **Confidence:** 4.75
- **Description:** The presence of the LDAP administrator REDACTED_PASSWORD_PLACEHOLDER option string '-w REDACTED_PASSWORD_PLACEHOLDER' indicates that the program supports receiving the LDAP administrator REDACTED_PASSWORD_PLACEHOLDER via command-line arguments. This may lead to REDACTED_PASSWORD_PLACEHOLDER exposure in process lists or logs.
- **Keywords:** -w REDACTED_PASSWORD_PLACEHOLDER, lp_ldap_admin_dn
- **Notes:** Review the program usage to ensure passwords are not passed via the command line

---
### system-accounts-REDACTED_PASSWORD_PLACEHOLDER-file-access

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 7.0
- **Confidence:** 4.0
- **Description:** Due to security restrictions, direct access to the REDACTED_PASSWORD_PLACEHOLDER file is not possible. This file typically contains system account information and may include hardcoded REDACTED_PASSWORD_PLACEHOLDER passwords or privileged accounts in embedded systems. It is recommended to verify the file contents through alternative methods.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, etc/REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, user_accounts
- **Notes:** It is recommended to check whether the system configuration stores REDACTED_PASSWORD_PLACEHOLDER hashes in the shadow file, or to verify the contents of the REDACTED_PASSWORD_PLACEHOLDER file through other methods.

---
### potential-credentials-REDACTED_PASSWORD_PLACEHOLDER-fields

- **File/Directory Path:** `N/A`
- **Location:** `0x0040c28c-0x0040c2d9`
- **Risk Score:** 7.0
- **Confidence:** 4.0
- **Description:** Hard-coded REDACTED_PASSWORD_PLACEHOLDER field names 'REDACTED_PASSWORD_PLACEHOLDER' and 'REDACTED_PASSWORD_PLACEHOLDER' were detected, indicating the system may use preset administrator authentication logic. Although no direct hard-coded values were found, the presence of these fields requires further verification.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, USER_CFG
- **Notes:** Analyze authentication-related functions to confirm the presence of hardcoded values

---
### ssl-cert-path-vsftpd-pem

- **File/Directory Path:** `N/A`
- **Location:** `strings output`
- **Risk Score:** 7.0
- **Confidence:** 3.75
- **Description:** Discovered SSL certificate file path 'REDACTED_PASSWORD_PLACEHOLDER.pem'. If the certificate private REDACTED_PASSWORD_PLACEHOLDER is also stored here, there may be a risk of leakage.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.pem
- **Notes:** It is recommended to verify the permissions and content of the certificate files.

---
