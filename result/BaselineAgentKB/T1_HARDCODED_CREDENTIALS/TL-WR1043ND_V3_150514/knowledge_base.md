# TL-WR1043ND_V3_150514 (1 alerts)

---

### hardcoded-default-credentials

- **File/Directory Path:** `N/A`
- **Location:** `web/dynaform/custom.js`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Hardcoded default administrator credentials were found in the JavaScript configuration file: REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' and REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER'. These default credentials could potentially allow attackers to gain complete control of the device.
- **Code Snippet:**
  ```
  var default_usrname = "REDACTED_PASSWORD_PLACEHOLDER";
  var default_REDACTED_PASSWORD_PLACEHOLDER;
  ```
- **Keywords:** default_usrname, default_password, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** These are the factory default credentials for the device, which the user may not have changed.

---
