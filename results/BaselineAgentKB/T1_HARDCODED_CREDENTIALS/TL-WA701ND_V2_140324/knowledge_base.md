# TL-WA701ND_V2_140324 (2 alerts)

---

### hardcoded-credentials-shadow-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** The discovery that both REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER users share the same weak REDACTED_PASSWORD_PLACEHOLDER hash (MD5 encrypted) indicates the presence of hardcoded credentials. This hash value is vulnerable to brute-force attacks or rainbow table attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  REDACTED_PASSWORD_PLACEHOLDER:$1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/:10933:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, $1$$REDACTED_SECRET_KEY_PLACEHOLDER.H3/
- **Notes:** configuration_load

---
### empty-passwords-system-accounts

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:3-12`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** Multiple system accounts (bin, daemon, adm, etc.) have no REDACTED_PASSWORD_PLACEHOLDER set (::), which may lead to unauthorized access.
- **Code Snippet:**
  ```
  bin::10933:0:99999:7:::
  daemon::10933:0:99999:7:::
  adm::10933:0:99999:7:::
  ```
- **Keywords:** bin, daemon, adm, lp, sync, shutdown, halt, uucp, operator, nobody
- **Notes:** These accounts typically should not have login permissions, but risks still exist.

---
