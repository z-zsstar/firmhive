# _US_AC18V1.0BR_V15.03.05.05_multi_TD01.bin.extracted (7 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-credentials-webroot_ro-default.cfg

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 9.5
- **Confidence:** 9.5
- **Description:** Default administrator credentials found - REDACTED_PASSWORD_PLACEHOLDER: 'REDACTED_PASSWORD_PLACEHOLDER', REDACTED_PASSWORD_PLACEHOLDER empty. This allows anyone to access the router management interface using the default credentials.
- **Code Snippet:**
  ```
  sys.REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER=
  ```
- **Keywords:** sys.REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Immediately change all default credentials, especially for administrator accounts.

---
### hardcoded-credentials-etc-REDACTED_PASSWORD_PLACEHOLDER-shadow

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER, etc_ro/shadow`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER, etc_ro/shadow`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Hardcoded user credentials were found in the etc_ro/REDACTED_PASSWORD_PLACEHOLDER and etc_ro/shadow files, including encrypted passwords for REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, and user accounts. These passwords are stored using Unix crypt(3) hashes and may be vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, shadow, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, user
- **Notes:** System user REDACTED_PASSWORD_PLACEHOLDER

---
### wep-keys-webroot_ro-default.cfg

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Multiple WEP encryption keys were found set to '12345', which is an extremely insecure encryption method using weak passwords.
- **Code Snippet:**
  ```
  wl2g.ssid0.wep_key1=12345
  wl2g.ssid0.wep_key2=12345
  wl5g.ssid0.wep_key1=12345
  ```
- **Keywords:** wl2g.ssid0.wep_key1, wl2g.ssid0.wep_key2, wl5g.ssid0.wep_key1
- **Notes:** Disable WEP encryption and switch to WPA2 or WPA3.

---
### hardcoded-credentials-etc_ro-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Hardcoded user credentials, including REDACTED_PASSWORD_PLACEHOLDER and encrypted REDACTED_PASSWORD_PLACEHOLDER, were found in the etc_ro/REDACTED_PASSWORD_PLACEHOLDER file. The REDACTED_PASSWORD_PLACEHOLDER is stored in DES encryption format (tGqcT.qjxbEik). This encryption method is weak and may be vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  user:tGqcT.qjxbEik
  ```
- **Keywords:** user, tGqcT.qjxbEik
- **Notes:** System user REDACTED_PASSWORD_PLACEHOLDER.

---
### ftp-samba-credentials-webroot_ro-default.cfg

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Discovered default credentials for FTP and Samba services - REDACTED_PASSWORD_PLACEHOLDER: 'REDACTED_PASSWORD_PLACEHOLDER', REDACTED_PASSWORD_PLACEHOLDER: 'REDACTED_PASSWORD_PLACEHOLDER'.
- **Code Snippet:**
  ```
  usb.ftp.user=REDACTED_PASSWORD_PLACEHOLDER
  usb.ftp.pwd=REDACTED_PASSWORD_PLACEHOLDER
  usb.samba.user=REDACTED_PASSWORD_PLACEHOLDER
  usb.samba.pwd=REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** usb.ftp.pwd, usb.ftp.user, usb.samba.pwd, usb.samba.user
- **Notes:** Disable unnecessary services (such as FTP) or change their default credentials.

---
### nginx-config-etc_ro-nginx.conf

- **File/Directory Path:** `etc_ro/nginx/conf/nginx.conf`
- **Location:** `etc_ro/nginx/conf/nginx.conf`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** Service running privileges
- **Code Snippet:**
  ```
  user REDACTED_PASSWORD_PLACEHOLDER;
  ```
- **Keywords:** user REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Service execution permissions

---
### user-credentials-webroot_ro-default.cfg

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `webroot_ro/default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** Discovered basic user credentials - REDACTED_PASSWORD_PLACEHOLDER: 'user', REDACTED_PASSWORD_PLACEHOLDER: 'user'. This is another available low-privilege account.
- **Code Snippet:**
  ```
  sys.baseREDACTED_PASSWORD_PLACEHOLDER=user
  sys.baseuserpass=user
  ```
- **Keywords:** sys.baseREDACTED_PASSWORD_PLACEHOLDER, sys.baseuserpass
- **Notes:** User credentials.

---
