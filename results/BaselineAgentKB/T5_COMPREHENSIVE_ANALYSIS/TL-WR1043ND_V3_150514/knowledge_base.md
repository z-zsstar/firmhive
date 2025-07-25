# TL-WR1043ND_V3_150514 (1 alerts)

---

### hardcoded-credentials-customjs

- **File/Directory Path:** `N/A`
- **Location:** `web/dynaform/custom.js`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** Hardcoded default administrator credentials (REDACTED_PASSWORD_PLACEHOLDER: REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER: REDACTED_PASSWORD_PLACEHOLDER) were found in the web/dynaform/custom.js file. This allows attackers to easily obtain the device's default login credentials, potentially leading to unauthorized access.
- **Code Snippet:**
  ```
  var default_usrname = "REDACTED_PASSWORD_PLACEHOLDER";
  var default_REDACTED_PASSWORD_PLACEHOLDER;
  ```
- **Keywords:** default_usrname, default_password, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to enforce users to change the default REDACTED_PASSWORD_PLACEHOLDER upon first login or utilize device-unique default credentials.

---
