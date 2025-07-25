# TD-W8980_V1_150514 (5 alerts)

---

### hardcoded-credentials-vsftpd_REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Hardcoded FTP credentials were found in the vsftpd_REDACTED_PASSWORD_PLACEHOLDER file, containing multiple REDACTED_PASSWORD_PLACEHOLDER and plaintext REDACTED_PASSWORD_PLACEHOLDER pairs. These credentials may be used for FTP service authentication.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** These credentials appear to be for FTP service user authentication. It is recommended to change these default credentials immediately.

---
### storage-REDACTED_PASSWORD_PLACEHOLDER-credentials

- **File/Directory Path:** `N/A`
- **Location:** `etc/default_config.xml: (REDACTED_PASSWORD_PLACEHOLDER instance=1)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Default administrator credentials were found in the storage service configuration, with both REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER set to 'REDACTED_PASSWORD_PLACEHOLDER'.
- **Code Snippet:**
  ```
  <REDACTED_PASSWORD_PLACEHOLDER val=REDACTED_PASSWORD_PLACEHOLDER />
  <REDACTED_PASSWORD_PLACEHOLDER val=REDACTED_PASSWORD_PLACEHOLDER />
  ```
- **Keywords:** StorageService, UserAccount, REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** These credentials may be used to access the device's storage services.

---
### hardcoded-3g-credentials

- **File/Directory Path:** `N/A`
- **Location:** `etc/default_config.xml: (WANDevice instance=3)`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Hardcoded credentials for 3G dial-up were found in the default_config.xml file, with both REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER stored in plaintext.
- **Code Snippet:**
  ```
  <REDACTED_PASSWORD_PLACEHOLDER val=WAP@CINGULAR.COM />
  <REDACTED_PASSWORD_PLACEHOLDER val=CINGULAR1 />
  ```
- **Keywords:** WAP@CINGULAR.COM, CINGULAR1, 3G, dial-up
- **Notes:** These credentials are used for 3G dial-up connections and may be utilized for unauthorized network access.

---
### hardcoded-hash-REDACTED_PASSWORD_PLACEHOLDER.bak

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER.bak file contains system user credentials, including the MD5 REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user. Although the REDACTED_PASSWORD_PLACEHOLDER is hashed, it still constitutes sensitive information.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** MD5 hash can be cracked, it is recommended to change the REDACTED_PASSWORD_PLACEHOLDER and use a stronger hashing algorithm.

---
### voicemail-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/default_config.xml: (Line instance=1 and 2)`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** The default voicemail REDACTED_PASSWORD_PLACEHOLDER '123456' was found, which poses a low security risk.
- **Code Snippet:**
  ```
  <REDACTED_SECRET_KEY_PLACEHOLDER val="123456" />
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER, 123456, voicemail
- **Notes:** A simple numeric REDACTED_PASSWORD_PLACEHOLDER is vulnerable to brute-force attacks.

---
