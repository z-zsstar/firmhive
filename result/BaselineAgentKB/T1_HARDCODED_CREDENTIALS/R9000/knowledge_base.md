# R9000 (2 alerts)

---

### SSL-PrivateKey-uhttpd

- **File/Directory Path:** `N/A`
- **Location:** `./etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** A hardcoded RSA private REDACTED_PASSWORD_PLACEHOLDER was discovered in /etc/uhttpd.REDACTED_PASSWORD_PLACEHOLDER. This private REDACTED_PASSWORD_PLACEHOLDER is used for HTTPS communication, and its exposure could allow attackers to decrypt encrypted traffic or impersonate the device.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  ...
  ```
- **Keywords:** uhttpd.REDACTED_PASSWORD_PLACEHOLDER, RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** file_read

---
### Default-Credentials-aMule

- **File/Directory Path:** `N/A`
- **Location:** `./etc/aMule/amule.conf:6, ./etc/aMule/remote.conf:1`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_REDACTED_SECRET_KEY_PLACEHOLDER_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** ECPassword, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** configuration_load

---
