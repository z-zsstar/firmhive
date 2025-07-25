# TL-WA701ND_V2_140324 (2 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-shadow-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/shadow`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** In the .REDACTED_PASSWORD_PLACEHOLDER file, it was discovered that both the REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER users share the same MD5 REDACTED_PASSWORD_PLACEHOLDER hash value '$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/', indicating they likely use identical passwords. The hash algorithm type is '1' (MD5).
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, $1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** It is recommended to further verify whether the passwords for the REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER accounts are identical.

---
### REDACTED_PASSWORD_PLACEHOLDER-shadow-ap71-empty

- **File/Directory Path:** `etc/shadow`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER field for user 'ap71' was found empty in the .REDACTED_PASSWORD_PLACEHOLDER file, which may pose a security risk.
- **Code Snippet:**
  ```
  ap71::10933:0:99999:7:::
  ```
- **Keywords:** ap71
- **Notes:** It is recommended to ensure that the REDACTED_PASSWORD_PLACEHOLDER for the ap71 account is not empty.

---
