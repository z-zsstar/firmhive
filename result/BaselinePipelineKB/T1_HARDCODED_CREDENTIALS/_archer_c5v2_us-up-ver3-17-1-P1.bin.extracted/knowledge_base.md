# _archer_c5v2_us-up-ver3-17-1-P1.bin.extracted (4 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-unix_password-root_md5_hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 10.0
- **Description:** A REDACTED_PASSWORD_PLACEHOLDER hash for the REDACTED_PASSWORD_PLACEHOLDER user was found in the REDACTED_PASSWORD_PLACEHOLDER file. This hash is encrypted using the MD5 algorithm (identified by $1$). Although this is not a plaintext REDACTED_PASSWORD_PLACEHOLDER, MD5 hashes are relatively easy to crack, posing a security risk. Recommendations: 1) If this is a production system, change the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER immediately 2) Consider using a more secure hashing algorithm such as SHA-512 (identified by $6$) 3) Check whether other user accounts are using weak hashing algorithms.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER:15502:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, GTN.gpri, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER type: Unix REDACTED_PASSWORD_PLACEHOLDER hash; Hashing algorithm: MD5; Hash value: $1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER; Unencoded

---
### auth-base64_encoded_credentials

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** A hardcoded Base64-encoded REDACTED_PASSWORD_PLACEHOLDER string was found, used for encoding authentication information. This REDACTED_PASSWORD_PLACEHOLDER string is employed to combine the REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER, perform Base64 encoding, and then store the result in a cookie. This implementation poses security risks since Base64 is not encryption but merely encoding, which can be easily decoded to obtain plaintext credentials.
- **Code Snippet:**
  ```
  var keyStr = "REDACTED_PASSWORD_PLACEHOLDER";
  var auth = "Basic "+ Base64Encoding(REDACTED_PASSWORD_PLACEHOLDER + ":" + REDACTED_PASSWORD_PLACEHOLDER);
  document.cookie = "Authorization="+escape(auth)+";path=/"
  ```
- **Keywords:** keyStr, Base64Encoding, Authorization, document.cookie
- **Notes:** authentication_mechanism: Base64-encoded credentials; it is recommended to use more secure authentication mechanisms such as HTTPS and session tokens

---
### REDACTED_PASSWORD_PLACEHOLDER-unix_password-root_md5_hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/shadow:1`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** The encrypted REDACTED_PASSWORD_PLACEHOLDER for the REDACTED_PASSWORD_PLACEHOLDER user was found in the shadow file. The REDACTED_PASSWORD_PLACEHOLDER is encrypted using the MD5 algorithm (indicated by the $1$ prefix). While this is standard practice, it could still be cracked if the REDACTED_PASSWORD_PLACEHOLDER strength is insufficient.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER:15502:0:99999:7:::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER type: UNIX user REDACTED_PASSWORD_PLACEHOLDER; Hash algorithm: MD5; Hash value: $1$GTN.gpri$REDACTED_PASSWORD_PLACEHOLDER; Not encoded; REDACTED_PASSWORD_PLACEHOLDER strength check recommended

---
### auth-plaintext_password_handling

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** Plaintext REDACTED_PASSWORD_PLACEHOLDER handling logic detected, where the REDACTED_PASSWORD_PLACEHOLDER is directly obtained and processed via DOM with a maximum length restriction of 15 characters. The value of the REDACTED_PASSWORD_PLACEHOLDER field (REDACTED_PASSWORD_PLACEHOLDER) is directly used for authentication without additional hashing.
- **Code Snippet:**
  ```
  var REDACTED_PASSWORD_PLACEHOLDER = $("REDACTED_PASSWORD_PLACEHOLDER").value;
  if(!REDACTED_SECRET_KEY_PLACEHOLDER(REDACTED_PASSWORD_PLACEHOLDER.value))
  var REDACTED_PASSWORD_PLACEHOLDER = $("REDACTED_PASSWORD_PLACEHOLDER");
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_SECRET_KEY_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, PCSubWin
- **Notes:** authentication_mechanism

---
