# FH1201 (5 alerts)

---

### hardcoded-webadmin-credentials

- **File/Directory Path:** `N/A`
- **Location:** `webroot/nvram_default.cfg`
- **Risk Score:** 9.5
- **Confidence:** 9.5
- **Description:** Hardcoded web management credentials were found in webroot/nvram_default.cfg: http_REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER (plaintext) and REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER (base64-encoded 'REDACTED_PASSWORD_PLACEHOLDER'). These credentials could potentially be used for unauthorized administrative access.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER
  http_REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** http_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, YWRtaW4=
- **Notes:** YWRtaW4= is the base64 encoding of 'REDACTED_PASSWORD_PLACEHOLDER'.

---
### hardcoded-credentials-shadow

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/shadow:1`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** In the /etc_ro/shadow file, the REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER account was found, encrypted using MD5. These credentials could potentially allow privilege escalation attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, hash, shadow
- **Notes:** The repeated occurrence of the REDACTED_PASSWORD_PLACEHOLDER account's REDACTED_PASSWORD_PLACEHOLDER hash may indicate that the default credentials have not been changed.

---
### hardcoded-credentials-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** Multiple hardcoded user accounts and REDACTED_PASSWORD_PLACEHOLDER hashes were found in the /etc_ro/REDACTED_PASSWORD_PLACEHOLDER file, including REDACTED_PASSWORD_PLACEHOLDER, support, user, and REDACTED_PASSWORD_PLACEHOLDER accounts. These hashes use DES and MD5 encryption and may be vulnerable to brute-force attacks to obtain plaintext passwords.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, support, user, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, hash
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER hashing uses DES and MD5 encryption, which can be cracked using tools such as John the Ripper.

---
### hardcoded-wifi-credentials

- **File/Directory Path:** `N/A`
- **Location:** `webroot/nvram_default.cfg`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Multiple hardcoded WiFi WPA-PSK passwords were found in webroot/nvram_default.cfg: REDACTED_PASSWORD_PLACEHOLDER. These weak passwords could be susceptible to brute-force attacks.
- **Code Snippet:**
  ```
  wl.0.s.REDACTED_PASSWORD_PLACEHOLDER.pass=REDACTED_PASSWORD_PLACEHOLDER
  wl.5.s.REDACTED_PASSWORD_PLACEHOLDER.pass=REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** wl.0.s.REDACTED_PASSWORD_PLACEHOLDER.pass, wl.5.s.REDACTED_PASSWORD_PLACEHOLDER.pass, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Multiple WiFi interfaces using the same weak REDACTED_PASSWORD_PLACEHOLDER

---
### default-wps-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `webroot/nvram_default.cfg`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The default WPS REDACTED_PASSWORD_PLACEHOLDER code REDACTED_PASSWORD_PLACEHOLDER was detected, which could be exploited for unauthorized WiFi network access.
- **Code Snippet:**
  ```
  wl.0.wps.REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  wl.5.wps.REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** wl.0.wps.REDACTED_PASSWORD_PLACEHOLDER, wl.5.wps.REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** WPS REDACTED_PASSWORD_PLACEHOLDER has not been modified to a random value

---
