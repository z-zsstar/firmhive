# TL-WR1043ND_V3_150514 (3 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-shadow

- **File/Directory Path:** `etc/shadow`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** Encrypted REDACTED_PASSWORD_PLACEHOLDER information for the REDACTED_PASSWORD_PLACEHOLDER user was found in the 'REDACTED_PASSWORD_PLACEHOLDER' file. The REDACTED_PASSWORD_PLACEHOLDER uses an MD5-based encryption algorithm (starting with '$1$'), with the specific value being '$1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER'. MD5 encryption is considered insufficiently secure in modern systems, particularly when REDACTED_PASSWORD_PLACEHOLDER strength is inadequate.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER:15502:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER, shadow
- **Notes:** Recommendations: 1. Check REDACTED_PASSWORD_PLACEHOLDER strength; 2. Upgrade to more secure encryption algorithms (such as SHA-256 or SHA-512); 3. If possible, consider disabling remote REDACTED_PASSWORD_PLACEHOLDER login.

---
### hardcoded_credential-dhcp6cctlkey-base64

- **File/Directory Path:** `etc/dhcp6cctlkey`
- **Location:** `./etc/dhcp6cctlkey`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A Base64-encoded string 'REDACTED_PASSWORD_PLACEHOLDER' was found in the file './etc/dhcp6cctlkey', which is highly likely to be a hardcoded REDACTED_PASSWORD_PLACEHOLDER or REDACTED_PASSWORD_PLACEHOLDER. Due to security restrictions, direct decoding is not possible. It is recommended to decode this string in a permitted environment to further verify its content.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** dhcp6cctlkey, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to decode this Base64 string in a permitted environment to further verify its content.

---
### REDACTED_PASSWORD_PLACEHOLDER-SMB-REDACTED_PASSWORD_PLACEHOLDER-file-path

- **File/Directory Path:** `usr/sbin/smbd`
- **Location:** `smbd (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Not available from strings output
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** configuration_load

---
