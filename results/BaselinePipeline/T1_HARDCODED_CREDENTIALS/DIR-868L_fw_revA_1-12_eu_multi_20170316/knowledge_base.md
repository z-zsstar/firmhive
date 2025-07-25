# DIR-868L_fw_revA_1-12_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (5 alerts)

---

### ssl-private-REDACTED_PASSWORD_PLACEHOLDER-stunnel.REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/stunnel.REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/stunnel.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** A hardcoded RSA private REDACTED_PASSWORD_PLACEHOLDER was found stored in the etc/stunnel.REDACTED_PASSWORD_PLACEHOLDER file. This private REDACTED_PASSWORD_PLACEHOLDER is used for SSL/TLS encrypted communication. If obtained by an attacker, it could lead to man-in-the-middle attacks and data breaches.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----...
  ```
- **Keywords:** stunnel.REDACTED_PASSWORD_PLACEHOLDER, RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to immediately replace this private REDACTED_PASSWORD_PLACEHOLDER and regenerate the certificate

---
### samba-REDACTED_PASSWORD_PLACEHOLDER-credentials-SAMBA.php

- **File/Directory Path:** `etc/services/SAMBA.php`
- **Location:** `etc/services/SAMBA.php:10-11`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Hardcoded administrator REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER found. The REDACTED_PASSWORD_PLACEHOLDER is retrieved from 'REDACTED_PASSWORD_PLACEHOLDER:1/name', and the REDACTED_PASSWORD_PLACEHOLDER is obtained from 'REDACTED_PASSWORD_PLACEHOLDER:1/REDACTED_PASSWORD_PLACEHOLDER'. These credentials are used to create Samba user accounts and set passwords.
- **Code Snippet:**
  ```
  $REDACTED_PASSWORD_PLACEHOLDER = query("REDACTED_PASSWORD_PLACEHOLDER:1/name");
  $user_REDACTED_PASSWORD_PLACEHOLDER = get("s", "REDACTED_PASSWORD_PLACEHOLDER:1/REDACTED_PASSWORD_PLACEHOLDER");
  ```
- **Keywords:** $REDACTED_PASSWORD_PLACEHOLDER, $user_REDACTED_PASSWORD_PLACEHOLDER, query, get, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Although the REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER are retrieved from the device configuration, they are hardcoded in the script for Samba account creation, posing a risk of leakage.

---
### ssl-certificate-stunnel_cert.pem

- **File/Directory Path:** `etc/stunnel_cert.pem`
- **Location:** `etc/stunnel_cert.pem`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** A self-signed SSL certificate was discovered stored in the etc/stunnel_cert.pem file. The certificate was issued by 'General REDACTED_PASSWORD_PLACEHOLDER CA' with a validity period from 2012 to 2032. It uses a weak signature algorithm (REDACTED_PASSWORD_PLACEHOLDER).
- **Code Snippet:**
  ```
  -----BEGIN CERTIFICATE-----...
  ```
- **Keywords:** stunnel_cert.pem, General REDACTED_PASSWORD_PLACEHOLDER CA, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to use a stronger signature algorithm (such as SHA-256) and reduce the certificate validity period.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-handling-mdb.php

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.php: line 34-44`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** Discovered administrator REDACTED_PASSWORD_PLACEHOLDER handling logic where the REDACTED_PASSWORD_PLACEHOLDER is retrieved from device configuration, URL-encoded, and then returned. Although the REDACTED_PASSWORD_PLACEHOLDER itself is not hardcoded, the handling logic exposes the storage and access method of the REDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  if(tolower($name) == "REDACTED_PASSWORD_PLACEHOLDER")
  {
  	show_result(UrlEncode(query("REDACTED_PASSWORD_PLACEHOLDER")));
  	$found = 1;
  	break;
  }
  ```
- **Keywords:** admin_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, UrlEncode
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER is not hardcoded, but the handling logic could be exploited to obtain administrator credentials.

---
### wifi-REDACTED_PASSWORD_PLACEHOLDER-mfc

- **File/Directory Path:** `usr/sbin/mfc`
- **Location:** `usr/sbin/mfc:initHIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.25
- **Description:** A hardcoded WiFi REDACTED_PASSWORD_PLACEHOLDER parameter was found in the init command of the MFC script. The script accepts wifipassword as the 9th parameter and stores it in the device configuration. This may result in the REDACTED_PASSWORD_PLACEHOLDER being stored in plaintext on the device.
- **Keywords:** mfc, init, WIFIPWD, psk, wifipassword
- **Notes:** Further investigation is needed to examine how the devdata command stores these credentials and whether they can be extracted.

---
