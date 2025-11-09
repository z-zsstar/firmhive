# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (13 alerts)

---

### pem-private-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `webroot_ro/pem/privkeySrv.pem`
- **Location:** `webroot_ro/pem/privkeySrv.pem`
- **Risk Score:** 10.0
- **Confidence:** 9.5
- **Description:** Hardcoded RSA private REDACTED_PASSWORD_PLACEHOLDER found, stored in a PEM format file. This is a critical security risk as attackers could use this private REDACTED_PASSWORD_PLACEHOLDER to perform man-in-the-middle attacks, decrypt encrypted communications, or impersonate the server. The private REDACTED_PASSWORD_PLACEHOLDER is stored unencrypted and can be directly used.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  REDACTED_PASSWORD_PLACEHOLDER...
  ```
- **Keywords:** privkeySrv.pem, -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----, -----END RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
- **Notes:** It is recommended to immediately rotate this private REDACTED_PASSWORD_PLACEHOLDER and ensure the new private REDACTED_PASSWORD_PLACEHOLDER is not hardcoded in the firmware. Check if any services are currently using this private REDACTED_PASSWORD_PLACEHOLDER.

---
### pptp-client-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Location:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** The PPTP client configuration file contains a hardcoded REDACTED_PASSWORD_PLACEHOLDER '456', which is a very simple REDACTED_PASSWORD_PLACEHOLDER and can be easily brute-forced.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER=456
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER.txt, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Immediately change the passwords for all PPTP servers and clients.

---
### httpd-REDACTED_PASSWORD_PLACEHOLDER-credentials

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd strings output`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** HTTP REDACTED_PASSWORD_PLACEHOLDER credentials
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** HTTP REDACTED_PASSWORD_PLACEHOLDER credentials

---
### pptp-server-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Location:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Risk Score:** 8.5
- **Confidence:** 9.5
- **Description:** Hardcoded REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' was found in the PPTP server configuration file, and this REDACTED_PASSWORD_PLACEHOLDER was reused three times. This could potentially lead to unauthorized access to the VPN server.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER.txt, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** PPTP server REDACTED_PASSWORD_PLACEHOLDER

---
### shadow-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/shadow`
- **Location:** `etc_ro/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** The file contains a hardcoded REDACTED_PASSWORD_PLACEHOLDER user REDACTED_PASSWORD_PLACEHOLDER hash. The REDACTED_PASSWORD_PLACEHOLDER is encrypted using MD5 (indicated by '$1$'). The format is '$id$salt$hash', where 'OVhtCyFa' is the salt and 'REDACTED_PASSWORD_PLACEHOLDER' is the hash. This is a sensitive REDACTED_PASSWORD_PLACEHOLDER that could be used for privilege escalation if cracked.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER, etc_ro/shadow
- **Notes:** UNIX REDACTED_PASSWORD_PLACEHOLDER hash (MD5)

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 8.5
- **Confidence:** 7.75
- **Description:** UNIX REDACTED_PASSWORD_PLACEHOLDER hash (MD5)
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1
- **Notes:** All discovered passwords are encrypted hash values and require further cracking to obtain the plaintext passwords.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:2`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Discovered the encrypted REDACTED_PASSWORD_PLACEHOLDER for the REDACTED_PASSWORD_PLACEHOLDER user, using the DES encryption algorithm (6HgsSsJIEOc2U). The REDACTED_PASSWORD_PLACEHOLDER hash may be vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, 6HgsSsJIEOc2U
- **Notes:** All discovered passwords are encrypted hashes and require further cracking to obtain the plaintext passwords.

---
### REDACTED_PASSWORD_PLACEHOLDER-support-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:3`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Discovered the encrypted REDACTED_PASSWORD_PLACEHOLDER of the support user, using the DES encryption algorithm (Ead09Ca6IhzZY). The REDACTED_PASSWORD_PLACEHOLDER hash may be vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  support:Ead09Ca6IhzZY:0:0:support:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** support, Ead09Ca6IhzZY
- **Notes:** All discovered passwords are encrypted hashes and require further cracking to obtain the plaintext passwords.

---
### REDACTED_PASSWORD_PLACEHOLDER-user-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:4`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** The encrypted REDACTED_PASSWORD_PLACEHOLDER for the user account was discovered, using the DES encryption algorithm (tGqcT.qjxbEik). The REDACTED_PASSWORD_PLACEHOLDER hash may be vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  user:tGqcT.qjxbEik:0:0:user:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** user, tGqcT.qjxbEik
- **Notes:** All discovered passwords are encrypted hashes and require further cracking to obtain the plaintext passwords.

---
### httpd-encryption-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd strings output`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** Found hardcoded encryption REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER\\\\\\\\\\\\\\\\\\\\\\\\A' which appears to be used for cryptographic operations.
- **Code Snippet:**
  ```
  encryption_REDACTED_PASSWORD_PLACEHOLDER\\\\\\\\\\\\\\\\\\\\\\\\A
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER\\\\\\\\\\\\\\\\\\\\\\\\A
- **Notes:** Encryption REDACTED_PASSWORD_PLACEHOLDER

---
### REDACTED_PASSWORD_PLACEHOLDER-nobody-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:5`
- **Risk Score:** 7.5
- **Confidence:** 7.75
- **Description:** Discovered the encrypted REDACTED_PASSWORD_PLACEHOLDER for the nobody user, using the DES encryption algorithm (VBcCXSNG7zBAY). The REDACTED_PASSWORD_PLACEHOLDER hash may be vulnerable to brute-force attacks.
- **Code Snippet:**
  ```
  nobody:VBcCXSNG7zBAY:0:0:nobody:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** nobody, VBcCXSNG7zBAY
- **Notes:** All discovered passwords are encrypted hashes and require further cracking to obtain the plaintext passwords.

---
### httpd-wps-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd strings output`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** WPS REDACTED_PASSWORD_PLACEHOLDER
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** WPS REDACTED_PASSWORD_PLACEHOLDER

---
### httpd-wifi-credentials

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd strings output`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Found potential default WiFi credentials with SSID 'Tenda' and REDACTED_PASSWORD_PLACEHOLDER '12345'. These could allow unauthorized network access if unchanged.
- **Code Snippet:**
  ```
  wl2g_bss_wpapsk_psk_old=12345
  ```
- **Keywords:** Tenda, 12345, wl2g_bss_wpapsk_psk_old
- **Notes:** WiFi credentials

---
