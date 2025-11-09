# Archer_C50 (5 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-backup-REDACTED_PASSWORD_PLACEHOLDER-hash

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Hardcoded administrator account REDACTED_PASSWORD_PLACEHOLDER hash found in the REDACTED_PASSWORD_PLACEHOLDER.bak file. The hash uses the $1$ prefix, indicating MD5 encryption. The REDACTED_PASSWORD_PLACEHOLDER hash is vulnerable to brute-force attacks by cracking tools.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER User:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$
- **Notes:** System user REDACTED_PASSWORD_PLACEHOLDER hash.

---
### vsftpd-plaintext-credentials

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.5
- **Confidence:** 9.5
- **Description:** Plaintext FTP credentials were found in the vsftpd_REDACTED_PASSWORD_PLACEHOLDER file, including weak REDACTED_PASSWORD_PLACEHOLDER combinations such as REDACTED_PASSWORD_PLACEHOLDER/1234 and guest/guest. These credentials can be directly used to log in to the FTP service.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest
- **Notes:** FTP plaintext credentials

---
### telnet-default-enable

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/init.d/rcS:39`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** The telnet service is enabled by default, posing a potential risk of unauthorized access. It executes unconditionally and triggers during system startup.
- **Code Snippet:**
  ```
  telnetd
  ```
- **Keywords:** telnetd
- **Notes:** Network service configuration

---
### rcs-REDACTED_PASSWORD_PLACEHOLDER-copy

- **File/Directory Path:** `etc/init.d/rcS`
- **Location:** `etc/init.d/rcS:17`
- **Risk Score:** 7.0
- **Confidence:** 9.5
- **Description:** Sensitive file operation detected: copying REDACTED_PASSWORD_PLACEHOLDER.bak to /var/REDACTED_PASSWORD_PLACEHOLDER. This may expose system user information. The operation executes unconditionally and is triggered during system startup.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, /var/REDACTED_PASSWORD_PLACEHOLDER, cp -p
- **Notes:** Check the contents of the REDACTED_PASSWORD_PLACEHOLDER.bak file to confirm whether it contains sensitive user information.

---
### wireless-default-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/RT2860AP.dat, etc/RT2860AP5G.dat`
- **Location:** `etc/RT2860AP.dat, etc/RT2860AP5G.dat`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The MeshDefaultkey=1 setting found in the wireless configuration files (RT2860AP.dat and RT2860AP5G.dat) may indicate the use of default wireless encryption keys.
- **Code Snippet:**
  ```
  MeshDefaultkey=1
  ```
- **Keywords:** RT2860AP.dat, RT2860AP5G.dat, MeshDefaultkey
- **Notes:** Check the wireless encryption settings and ensure a strong REDACTED_PASSWORD_PLACEHOLDER is used instead of the default REDACTED_PASSWORD_PLACEHOLDER.

---
