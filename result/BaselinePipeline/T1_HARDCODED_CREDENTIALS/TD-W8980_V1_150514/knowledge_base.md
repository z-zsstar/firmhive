# TD-W8980_V1_150514 (6 alerts)

---

### FTP-credentials-vsftpd_REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Hardcoded FTP user credentials were found in the etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER file, formatted as 'REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER:privilege:status'. These are authentication details stored in plaintext, which could potentially be exploited for unauthorized access to the FTP service.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** The credentials are stored in plaintext, posing a serious security risk. It is recommended to immediately change all passwords and implement a secure REDACTED_PASSWORD_PLACEHOLDER storage mechanism.

---
### default-credentials-cli

- **File/Directory Path:** `usr/bin/cli`
- **Location:** `usr/bin/cli`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Default credentials for REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER/user were found hardcoded in the /usr/bin/cli file. These credentials appear in multiple configuration strings and may be used for system authentication.
- **Keywords:** RootName, RootPwd, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, rootName, rootPwd, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to further verify the discovered hard-coded credentials, especially the base64-encoded REDACTED_PASSWORD_PLACEHOLDER fields which may require decoding. Additionally, checks should be performed to determine whether these credentials are being used during system runtime.

---
### PPPoE-credentials-cli

- **File/Directory Path:** `usr/bin/cli`
- **Location:** `usr/bin/cli`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In the /usr/bin/cli file, REDACTED_PASSWORD_PLACEHOLDER fields were found in the PPPoE authentication configuration, including both plaintext passwords and base64-encoded REDACTED_PASSWORD_PLACEHOLDER options. This information could potentially be used for WAN connection authentication.
- **Keywords:** --REDACTED_PASSWORD_PLACEHOLDER, --safepassword, REDACTED_PASSWORD_PLACEHOLDER=%s, X_TPLINK_PreSharedKey
- **Notes:** PPPoE credentials

---
### WEP-WPA-credentials-cli

- **File/Directory Path:** `usr/bin/cli`
- **Location:** `usr/bin/cli`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The WEP/WPA pre-shared REDACTED_PASSWORD_PLACEHOLDER configuration was found in the /usr/bin/cli file, including plaintext and base64-encoded options for wireless network security settings.
- **Keywords:** --wepkey, --pskkey, WEPKey, X_TPLINK_PreSharedKey
- **Notes:** It is recommended to decode the base64-encoded REDACTED_PASSWORD_PLACEHOLDER field and verify its security.

---
### MD5-hash-REDACTED_PASSWORD_PLACEHOLDER.bak

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash of the REDACTED_PASSWORD_PLACEHOLDER user was found in the etc/REDACTED_PASSWORD_PLACEHOLDER.bak file. The hash uses the $1$ prefix, indicating MD5 encryption. Although the REDACTED_PASSWORD_PLACEHOLDER hash is not in plaintext, it can be cracked through brute force. If the system allows the REDACTED_PASSWORD_PLACEHOLDER user to log in, this may pose a security risk.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** It is recommended to check whether the system allows REDACTED_PASSWORD_PLACEHOLDER user login, and consider changing the REDACTED_PASSWORD_PLACEHOLDER or disabling the account.

---
### Radius-credentials-cli

- **File/Directory Path:** `usr/bin/cli`
- **Location:** `usr/bin/cli`
- **Risk Score:** 7.5
- **Confidence:** 7.25
- **Description:** Radius credentials found in the /usr/bin/cli file, potentially used for wireless network authentication.
- **Keywords:** X_TPLINK_REDACTED_PASSWORD_PLACEHOLDER, Radius_key
- **Notes:** Recommend checking whether these credentials are used during system operation and consider changing the REDACTED_PASSWORD_PLACEHOLDER.

---
