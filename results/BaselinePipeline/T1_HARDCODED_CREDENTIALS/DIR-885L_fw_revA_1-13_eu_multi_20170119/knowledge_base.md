# DIR-885L_fw_revA_1-13_eu_multi_REDACTED_PASSWORD_PLACEHOLDER (6 alerts)

---

### SSL-TLS-PrivateKey-stunnel.REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/stunnel.REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc/stunnel.REDACTED_PASSWORD_PLACEHOLDER:1-27`
- **Risk Score:** 10.0
- **Confidence:** 9.0
- **Description:** SSL/TLS Private REDACTED_PASSWORD_PLACEHOLDER
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER
  -----END RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER-----
  ```
- **Keywords:** stunnel.REDACTED_PASSWORD_PLACEHOLDER, BEGIN RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER, PEM, 2048 bit
- **Notes:** SSL/TLS Private REDACTED_PASSWORD_PLACEHOLDER

---
### Plaintext-REDACTED_PASSWORD_PLACEHOLDER-onepage.php

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Plaintext REDACTED_PASSWORD_PLACEHOLDER
- **Code Snippet:**
  ```
  ajaxObj.sendRequest("register_send.php", "act=signup&lang=en"+"&outemail="+OBJ("user_Account").value+"&REDACTED_PASSWORD_PLACEHOLDER="+OBJ("REDACTED_PASSWORD_PLACEHOLDER").value+"&firstname="+OBJ("user_FirstName").value+"&lastname="+OBJ("user_LastName").value);
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, escape(REDACTED_PASSWORD_PLACEHOLDER), user_Account, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Plaintext REDACTED_PASSWORD_PLACEHOLDER

---
### WPA-PSK-REDACTED_PASSWORD_PLACEHOLDER-fatlady.php

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Wi-Fi PSK REDACTED_PASSWORD_PLACEHOLDER
- **Code Snippet:**
  ```
  $REDACTED_PASSWORD_PLACEHOLDER=query("nwkey/psk/REDACTED_PASSWORD_PLACEHOLDER");
  ```
- **Keywords:** nwkey/psk/REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Wi-Fi PSK REDACTED_PASSWORD_PLACEHOLDER

---
### PPP-Credentials-fatlady.php

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.php`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** PPP REDACTED_PASSWORD_PLACEHOLDER
- **Code Snippet:**
  ```
  $REDACTED_PASSWORD_PLACEHOLDER=query("ppp4/REDACTED_PASSWORD_PLACEHOLDER");
  ```
- **Keywords:** ppp4/REDACTED_PASSWORD_PLACEHOLDER, ppp6/REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** PPP credentials should be securely stored and not exposed in configuration files.

---
### Digest-Authentication-postxml.js

- **File/Directory Path:** `REDACTED_PASSWORD_PLACEHOLDER.js`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.js`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Digest authentication with REDACTED_PASSWORD_PLACEHOLDER exposure in JavaScript (postxml.js). While the REDACTED_PASSWORD_PLACEHOLDER is processed through a DIGEST function, it's still exposed in the payload construction.
- **Code Snippet:**
  ```
  var payload = "id="+user+"&REDACTED_PASSWORD_PLACEHOLDER="+DIGEST;
  ```
- **Keywords:** DIGEST, REDACTED_PASSWORD_PLACEHOLDER=, payload
- **Notes:** Authentication REDACTED_PASSWORD_PLACEHOLDER

---
### SSL-Certificate-stunnel_cert.pem

- **File/Directory Path:** `etc/stunnel_cert.pem`
- **Location:** `etc/stunnel_cert.pem:1-45`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** SSL/TLS Certificate
- **Keywords:** stunnel_cert.pem, BEGIN CERTIFICATE, General REDACTED_PASSWORD_PLACEHOLDER CA, General Router, 2048 bit
- **Notes:** SSL/TLS Certificate

20-year validity period increases exposure risk. Consider replacing with CA-signed certificate.

---
