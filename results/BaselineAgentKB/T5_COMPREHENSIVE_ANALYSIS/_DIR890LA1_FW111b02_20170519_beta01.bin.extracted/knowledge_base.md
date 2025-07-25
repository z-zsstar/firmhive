# _DIR890LA1_FW111b02_REDACTED_PASSWORD_PLACEHOLDER_beta01.bin.extracted (3 alerts)

---

### hardcoded-private-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/stunnel.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.0
- **Confidence:** 8.75
- **Description:** The firmware contains a hardcoded RSA private REDACTED_PASSWORD_PLACEHOLDER for stunnel with world-writable permissions. This allows potential decryption of all TLS traffic if the REDACTED_PASSWORD_PLACEHOLDER is compromised, and affects all devices using this firmware image.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** stunnel, private REDACTED_PASSWORD_PLACEHOLDER, RSA, TLS
- **Notes:** configuration_load

---
### stunnel-insecure-config

- **File/Directory Path:** `N/A`
- **Location:** `etc/stunnel.conf`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  cert = /etc/stunnel_cert.pem
  REDACTED_PASSWORD_PLACEHOLDER =/etc/stunnel.REDACTED_PASSWORD_PLACEHOLDER
  pid = /var/run/stunnel.pid
  setuid = 0
  setgid = 0
  
  debug = 7
  output = /var/log/stunnel.log
  ```
- **Keywords:** stunnel, setuid, debug, https
- **Notes:** configuration_load

---
### web-log-symlinks

- **File/Directory Path:** `N/A`
- **Location:** `www/syslog.rg and www/tsyslog.rg`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The www directory contains symbolic links to system log files (/var/log/message and /var/log/tlogsmsg). If the web server follows symlinks, this could lead to information disclosure vulnerabilities by exposing system logs through the web interface.
- **Code Snippet:**
  ```
  lrwxrwxrwx 1 REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER 16 11HIDDEN 26  2019 syslog.rg -> /var/log/message
  lrwxrwxrwx 1 REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER 17 11HIDDEN 26  2019 tsyslog.rg -> /var/log/tlogsmsg
  ```
- **Keywords:** syslog.rg, tsyslog.rg, /var/log/message, /var/log/tlogsmsg
- **Notes:** Actual risk depends on web server configuration regarding symlink following and log file REDACTED_PASSWORD_PLACEHOLDER.

---
