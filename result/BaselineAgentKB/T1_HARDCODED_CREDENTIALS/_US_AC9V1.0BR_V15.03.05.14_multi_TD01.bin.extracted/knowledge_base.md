# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (5 alerts)

---

### hardcoded-credentials-shadow

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/shadow:1`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user was found in the /etc_ro/shadow file. This file typically contains more sensitive security information.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** shadow, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** The shadow file typically restricts access permissions, but in this firmware, it can be read by any user.

---
### hardcoded-wifi-passwords

- **File/Directory Path:** `N/A`
- **Location:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt:1-2, webroot_REDACTED_PASSWORD_PLACEHOLDER.txt:1-2`
- **Risk Score:** 9.0
- **Confidence:** 9.5
- **Description:** Hardcoded WiFi passwords were found in multiple web management interface configuration files, with the default passwords for both 2.4GHz and 5GHz networks set to 'REDACTED_PASSWORD_PLACEHOLDER', posing a severe security risk.
- **Code Snippet:**
  ```
  "wrlPwd": "REDACTED_PASSWORD_PLACEHOLDER",
  "wrlPwd_5g": "REDACTED_PASSWORD_PLACEHOLDER",
  "guestWrlPwd":"REDACTED_PASSWORD_PLACEHOLDER",
  "guestWrlPwd_5g":"REDACTED_PASSWORD_PLACEHOLDER"
  ```
- **Keywords:** wrlPwd, wrlPwd_5g, guestWrlPwd, guestWrlPwd_5g
- **Notes:** These passwords are extremely weak and reused across multiple locations.

---
### hardcoded-credentials-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:1-5`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Multiple hardcoded user accounts and their REDACTED_PASSWORD_PLACEHOLDER hashes were found in the /etc_ro/REDACTED_PASSWORD_PLACEHOLDER file, including REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, user, and nobody accounts. These hash values could potentially be cracked to obtain plaintext passwords.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, support, user, nobody
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER hashing uses DES and MD5 algorithms, which can be cracked using tools such as John the Ripper.

---
### base64-encoded-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `webroot_ro/goform/cloud.txt:1`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** A Base64-encoded REDACTED_PASSWORD_PLACEHOLDER 'NjE3MzA1NjI=' was found in webroot_ro/goform/cloud.txt, which decodes to 'REDACTED_PASSWORD_PLACEHOLDER'.
- **Code Snippet:**
  ```
  "REDACTED_PASSWORD_PLACEHOLDER":"NjE3MzA1NjI="
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, Base64
- **Notes:** Base64 encoding is not encryption and can be easily decoded to obtain the plaintext.

---
### vpn-ddnssamba-passwords

- **File/Directory Path:** `N/A`
- **Location:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt:1, webroot_REDACTED_PASSWORD_PLACEHOLDER.txt:1, webroot_REDACTED_PASSWORD_PLACEHOLDER.txt:1-3, webroot_REDACTED_PASSWORD_PLACEHOLDER.txt:1-2`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Multiple services were found with hardcoded passwords: VPN REDACTED_PASSWORD_PLACEHOLDER is 'REDACTED_PASSWORD_PLACEHOLDER', DDNS REDACTED_PASSWORD_PLACEHOLDER is '456', PPTP REDACTED_PASSWORD_PLACEHOLDER is 'REDACTED_PASSWORD_PLACEHOLDER', Samba passwords are '1asdf23' and 'rewrewf'.
- **Code Snippet:**
  ```
  "ddnsPwd":"456",
  "vpnPwd": "REDACTED_PASSWORD_PLACEHOLDER",
  "REDACTED_PASSWORD_PLACEHOLDER": "REDACTED_PASSWORD_PLACEHOLDER",
  "REDACTED_PASSWORD_PLACEHOLDER":"1asdf23",
  "guestpwd": "rewrewf"
  ```
- **Keywords:** ddnsPwd, vpnPwd, REDACTED_PASSWORD_PLACEHOLDER, guestpwd
- **Notes:** These passwords are weak and reused across multiple sites.

---
