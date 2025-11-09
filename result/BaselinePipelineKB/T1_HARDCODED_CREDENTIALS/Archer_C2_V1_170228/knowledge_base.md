# Archer_C2_V1_170228 (8 alerts)

---

### hardcoded-3g-passwords

- **File/Directory Path:** `N/A`
- **Location:** `web/js/3g.js`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Multiple hardcoded 3G connection credentials were discovered in the web/js/3g.js file. These credentials appear to be default passwords used by multiple mobile operators worldwide. The passwords are stored in plaintext and could potentially be exploited for unauthorized access to 3G network connections.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER : "clarogprs999"
  REDACTED_PASSWORD_PLACEHOLDER : "gprs"
  REDACTED_PASSWORD_PLACEHOLDER : "internet"
  REDACTED_PASSWORD_PLACEHOLDER : "web"
  REDACTED_PASSWORD_PLACEHOLDER : "REDACTED_PASSWORD_PLACEHOLDER"
  REDACTED_PASSWORD_PLACEHOLDER : "1234"
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, web/js/3g.js
- **Notes:** hardcoded_credential

---
### ipsec-preshared-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** hardcoded_credential
- **Code Snippet:**
  ```
  $.id("psk").value = "psk_key";
  ```
- **Keywords:** psk, ipsecConfig.htm, keyExM, authM
- **Notes:** hardcoded_credential

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 8.0
- **Confidence:** 8.25
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER hash ($1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/) for the REDACTED_PASSWORD_PLACEHOLDER user was discovered. This is an MD5 algorithm REDACTED_PASSWORD_PLACEHOLDER hash (identified by $1$) which is susceptible to brute-force attacks. The hash is located between the REDACTED_PASSWORD_PLACEHOLDER and user ID fields, conforming to the standard UNIX REDACTED_PASSWORD_PLACEHOLDER file format.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** It is recommended to change this REDACTED_PASSWORD_PLACEHOLDER immediately. MD5 hashing is relatively easy to crack, especially if the REDACTED_PASSWORD_PLACEHOLDER strength is insufficient.

---
### httpd-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-pattern

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd (HIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** The hardcoded administrator REDACTED_PASSWORD_PLACEHOLDER field pattern was discovered in the httpd binary file. This field appears in the string formatting template, indicating that the system may use the REDACTED_PASSWORD_PLACEHOLDER parameter to store or transmit administrator passwords.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER=%s, USER_CFG
- **Notes:** Although the REDACTED_PASSWORD_PLACEHOLDER pattern has been identified, the actual REDACTED_PASSWORD_PLACEHOLDER value may require runtime analysis to obtain.

---
### REDACTED_PASSWORD_PLACEHOLDER-md5-REDACTED_PASSWORD_PLACEHOLDER-hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Hardcoded user credentials were discovered in the backup REDACTED_PASSWORD_PLACEHOLDER file. The REDACTED_PASSWORD_PLACEHOLDER for the REDACTED_PASSWORD_PLACEHOLDER user was encrypted using DES (the $1$ prefix indicates an MD5 hash). Although this is an encrypted hash rather than plaintext, there remains a risk of brute-force attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$, REDACTED_PASSWORD_PLACEHOLDER.bak
- **Notes:** Recommendations: 1) Delete or secure this backup file 2) Change the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER 3) Consider using a more secure hashing algorithm such as SHA-256 or SHA-512

---
### httpd-user-REDACTED_PASSWORD_PLACEHOLDER-patterns

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** Discovered user REDACTED_PASSWORD_PLACEHOLDER storage pattern, including REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER fields. These fields appear in string formatting templates related to user authentication.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER=%s, USER_CFG
- **Notes:** These fields may be used for web interface user authentication

---
### httpd-basic-auth-implementation

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 7.75
- **Description:** The presence of HTTP header fields related to authentication (Authorization: Basic) and the definition of an authentication realm indicate the use of HTTP Basic Authentication.
- **Keywords:** Authorization, Basic, WWW-Authenticate: Basic realm="%s"
- **Notes:** HTTP Basic Authentication transmits credentials in Base64 encoding, making them vulnerable to interception and decoding.

---
### base64-auth-mechanism

- **File/Directory Path:** `N/A`
- **Location:** `web/frame/login.htm`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** authentication_mechanism
- **Code Snippet:**
  ```
  auth = "Basic "+Base64Encoding(REDACTED_PASSWORD_PLACEHOLDER+":"+REDACTED_PASSWORD_PLACEHOLDER);
  document.cookie = "Authorization=" + auth;
  ```
- **Keywords:** Base64Encoding, auth, REDACTED_PASSWORD_PLACEHOLDER, web/frame/login.htm
- **Notes:** authentication_mechanism

---
