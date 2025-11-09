# R9000 (7 alerts)

---

### SSL-TLS-Private-REDACTED_PASSWORD_PLACEHOLDER-uhttpd.REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 10.0
- **Confidence:** 9.0
- **Description:** A complete RSA private REDACTED_PASSWORD_PLACEHOLDER (PEM format) was found in the etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER file, used for SSL/TLS encrypted communication. If leaked, attackers could decrypt encrypted traffic or perform man-in-the-middle attacks.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  ...
  -----END RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  ```
- **Keywords:** uhttpd.REDACTED_PASSWORD_PLACEHOLDER, BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER, END RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** This is a complete RSA private REDACTED_PASSWORD_PLACEHOLDER and should be immediately removed or replaced in the production environment. It is recommended to check whether other services are using the same private REDACTED_PASSWORD_PLACEHOLDER.

---
### RADIUS-REDACTED_PASSWORD_PLACEHOLDER-dni-wifi-config

- **File/Directory Path:** `etc/dni-wifi-config`
- **Location:** `etc/dni-wifi-config`
- **Risk Score:** 9.0
- **Confidence:** 7.75
- **Description:** RADIUS Shared REDACTED_PASSWORD_PLACEHOLDER
- **Keywords:** radiusSerIp, radiusPort, radiusSecret
- **Notes:** The RADIUS shared REDACTED_PASSWORD_PLACEHOLDER value may be stored in plaintext or encoded form in other system configuration files.

---
### aMule-Default-REDACTED_PASSWORD_PLACEHOLDER-amule.conf

- **File/Directory Path:** `etc/aMule/amule.conf, etc/aMule/remote.conf`
- **Location:** `etc/aMule/amule.conf:3, etc/aMule/remote.conf:1`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** A hardcoded MD5 hash REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' was found in the etc/aMule/amule.conf and etc/aMule/remote.conf files, which decodes to 'REDACTED_PASSWORD_PLACEHOLDER'. This is a well-known default REDACTED_PASSWORD_PLACEHOLDER hash that could lead to unauthorized access.
- **Keywords:** ECPassword, REDACTED_PASSWORD_PLACEHOLDER, ProxyPassword
- **Notes:** Default REDACTED_PASSWORD_PLACEHOLDER Hash

---
### WEP-WPA-Keys-dni-wifi-config

- **File/Directory Path:** `etc/dni-wifi-config`
- **Location:** `etc/dni-wifi-config: multiple locations`
- **Risk Score:** 8.0
- **Confidence:** 7.75
- **Description:** WEP/WPA wireless REDACTED_PASSWORD_PLACEHOLDER configurations were found in the etc/dni-wifi-config file. These keys may permit unauthorized network access.
- **Keywords:** wep_key, wpa_key_mgmt, radiusSecret
- **Notes:** The wireless network REDACTED_PASSWORD_PLACEHOLDER is handled in multiple configuration files and scripts.

---
### WiFi-PSK-dni-wifi-config

- **File/Directory Path:** `etc/dni-wifi-config`
- **Location:** `etc/dni-wifi-config`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** WiFi pre-shared REDACTED_PASSWORD_PLACEHOLDER (PSK) configuration items were found in the etc/dni-wifi-config file, including the values of _wpa2_psk, _wpas_psk, and _wpa1_psk. These values may contain actual WiFi passwords.
- **Keywords:** _wpa2_psk, _wpas_psk, _wpa1_psk
- **Notes:** Further analysis of the dniconfig tool or configuration files is required to obtain the actual PSK value.

---
### OpenVPN-Keys-openvpn

- **File/Directory Path:** `etc/init.d/openvpn`
- **Location:** `etc/init.d/openvpn: multiple locations`
- **Risk Score:** 8.0
- **Confidence:** 6.5
- **Description:** OpenVPN REDACTED_PASSWORD_PLACEHOLDER and certificate configurations (server.REDACTED_PASSWORD_PLACEHOLDER, client.REDACTED_PASSWORD_PLACEHOLDER, ca.crt) were found in the etc/init.d/openvpn file. If leaked, they could potentially allow VPN access.
- **Keywords:** server.REDACTED_PASSWORD_PLACEHOLDER, client.REDACTED_PASSWORD_PLACEHOLDER, ca.crt
- **Notes:** VPN credentials are handled in the OpenVPN initialization script.

---
### Email-Credentials-email_log

- **File/Directory Path:** `etc/email/email_log`
- **Location:** `etc/email/email_log:3`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Email credentials (email_password, email_REDACTED_PASSWORD_PLACEHOLDER) obtained via the nvram command were found in the etc/email/email_log file. This may expose email account credentials.
- **Keywords:** email_password, email_REDACTED_PASSWORD_PLACEHOLDER, email_endis_auth
- **Notes:** Credentials are dynamically obtained rather than hardcoded, yet they still exist within the configuration.

---
