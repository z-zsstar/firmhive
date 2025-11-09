# Archer_C50 (14 alerts)

---

### hardcoded_creds-ftp_admin

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 10.0
- **Confidence:** 10.0
- **Description:** Hardcoded FTP user 'REDACTED_PASSWORD_PLACEHOLDER' with REDACTED_PASSWORD_PLACEHOLDER '1234', flag value 1:1 indicates potential full permissions.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER:1234

---
### hardcoded_creds-ftp_vsftpd_REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** Multiple sets of hardcoded FTP credentials were found in the vsftpd_REDACTED_PASSWORD_PLACEHOLDER file, formatted as 'REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER:flag1:flag2'. The flag values likely indicate permission levels (1:1 represents full privileges). These credentials can be directly used for FTP service authentication, posing a critical security risk.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** It is recommended to change these default credentials immediately, especially as the REDACTED_PASSWORD_PLACEHOLDER account using the simple REDACTED_PASSWORD_PLACEHOLDER '1234' poses a high risk.

---
### unix_creds-admin_md5_hash_critical

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Risk Score:** 9.5
- **Confidence:** 9.5
- **Description:** The MD5 REDACTED_PASSWORD_PLACEHOLDER hash of the REDACTED_PASSWORD_PLACEHOLDER user was found in the REDACTED_PASSWORD_PLACEHOLDER.bak file, which constitutes a critical security vulnerability. Attackers could attempt to crack this hash to gain REDACTED_PASSWORD_PLACEHOLDER privileges. The hash value is: $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$
- **Notes:** It is recommended to immediately change the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER and delete backup files containing plaintext or hashed passwords. Consider using more secure REDACTED_PASSWORD_PLACEHOLDER hashing algorithms such as SHA-512.

---
### hardcoded_isp_credentials

- **File/Directory Path:** `N/A`
- **Location:** `web/js/3g.js`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** Multiple hardcoded ISP credentials were found in the 3g.js file, which are default authentication details for various mobile carriers stored in plaintext and could potentially be used for unauthorized access to 3G/4G network services.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER: "clarogprs",
  REDACTED_PASSWORD_PLACEHOLDER: "clarogprs999"
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, web/js/3g.js
- **Notes:** Affecting multiple global operators. These credentials should be removed or encrypted.

---
### hardcoded_creds-ftp_test

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 9.0
- **Confidence:** 10.0
- **Description:** Hardcoded FTP user 'test' with REDACTED_PASSWORD_PLACEHOLDER 'test', flag value 1:1 indicates potential full permissions.
- **Keywords:** test:test

---
### unix_creds-admin_md5_hash

- **File/Directory Path:** `N/A`
- **Location:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak:1`
- **Risk Score:** 8.5
- **Confidence:** 8.75
- **Description:** Discovered the MD5 encrypted REDACTED_PASSWORD_PLACEHOLDER hash (prefix $1$) for the REDACTED_PASSWORD_PLACEHOLDER user. This user has REDACTED_PASSWORD_PLACEHOLDER privileges (UID 0), and the REDACTED_PASSWORD_PLACEHOLDER hash is vulnerable to brute force or dictionary attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** It is recommended to check if the system still uses this account and consider changing the REDACTED_PASSWORD_PLACEHOLDER. MD5 hashes are relatively easy to crack.

---
### hardcoded_creds-ftp_guest

- **File/Directory Path:** `N/A`
- **Location:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 8.0
- **Confidence:** 10.0
- **Description:** Hardcoding the FTP user 'guest' and its REDACTED_PASSWORD_PLACEHOLDER 'guest', with a flag value of 0:0 indicating potential permission restrictions.
- **Keywords:** guest:guest

---
### default_admin_authentication

- **File/Directory Path:** `N/A`
- **Location:** `web/frame/login.htm`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Default administrator authentication mechanism detected, with the REDACTED_PASSWORD_PLACEHOLDER defaulting to 'REDACTED_PASSWORD_PLACEHOLDER' and REDACTED_PASSWORD_PLACEHOLDER authentication logic exposed. Although there is no hardcoded REDACTED_PASSWORD_PLACEHOLDER, the authentication mechanism poses a risk.
- **Code Snippet:**
  ```
  if (REDACTED_PASSWORD_REDACTED_SECRET_KEY_PLACEHOLDER) 
  REDACTED_PASSWORD_PLACEHOLDER.value = "REDACTED_PASSWORD_PLACEHOLDER";
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, web/frame/login.htm
- **Notes:** Default administrator REDACTED_PASSWORD_PLACEHOLDERs may facilitate brute force attacks.

---
### admin_auth_fields

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd (HIDDEN)`
- **Risk Score:** 8.0
- **Confidence:** 7.25
- **Description:** Hardcoded administrator REDACTED_PASSWORD_PLACEHOLDER field 'REDACTED_PASSWORD_PLACEHOLDER' and REDACTED_PASSWORD_PLACEHOLDER field 'REDACTED_PASSWORD_PLACEHOLDER' were identified, which are used for web interface authentication. Although the REDACTED_PASSWORD_PLACEHOLDER value is not directly displayed, logic for REDACTED_PASSWORD_PLACEHOLDER storage and verification exists.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, USER_CFG, http_auth_doAuth
- **Notes:** Further analysis of the authentication logic is required to confirm the REDACTED_PASSWORD_PLACEHOLDER storage method.

---
### wireless_security

- **File/Directory Path:** `N/A`
- **Location:** `web/main/wlSec.htm`
- **Risk Score:** 7.5
- **Confidence:** 7.5
- **Description:** authentication_mechanism
- **Code Snippet:**
  ```
  <p><b class="item L T T_wlpwd">REDACTED_PASSWORD_PLACEHOLDER:</b> <input type=text id=pskSecret class=text value="" size="40" maxlength="64" /></p>
  ```
- **Keywords:** WEP, WPA, PSK, authType, keyType, web/main/wlSec.htm
- **Notes:** The wireless security implementation should be reviewed for vulnerabilities.

---
### user_auth_fields

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd (HIDDEN)`
- **Risk Score:** 7.5
- **Confidence:** 6.75
- **Description:** The discovery of common user authentication fields 'REDACTED_PASSWORD_PLACEHOLDER' and 'REDACTED_PASSWORD_PLACEHOLDER' indicates the system supports multiple user roles. Similarly, no direct REDACTED_PASSWORD_PLACEHOLDER values are displayed, but relevant processing logic exists.
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, USER_CFG, http_rpm_auth_main
- **Notes:** check if user passwords are vulnerable to brute-force attacks

---
### pppoe_authentication

- **File/Directory Path:** `N/A`
- **Location:** `web/main/pppoe.htm`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Discovered PPPoE authentication processing logic containing REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER form fields. While no hardcoded credentials were found, the authentication mechanism requires security review.
- **Code Snippet:**
  ```
  <p><b class="item L T T_pppusr">PPP REDACTED_PASSWORD_PLACEHOLDER:</b><input type="text" class="text" size="15" id="REDACTED_PASSWORD_PLACEHOLDER" maxlength="63" /></p>
  <p><b class="item L T T_ppppwd">PPP REDACTED_PASSWORD_PLACEHOLDER:</b><input type="REDACTED_PASSWORD_PLACEHOLDER" class="text" size="15" id="pwd" maxlength="63" /></p>
  ```
- **Keywords:** pppoe, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, web/main/pppoe.htm, web/main/ethWan.htm
- **Notes:** The authentication mechanism should be reviewed for potential security vulnerabilities.

---
### usb_storage_credentials

- **File/Directory Path:** `N/A`
- **Location:** `REDACTED_PASSWORD_PLACEHOLDER.htm`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** authentication_mechanism
- **Code Snippet:**
  ```
  <p><b class="item L T" id="t_newpwd">New REDACTED_PASSWORD_PLACEHOLDER:</b><input type="REDACTED_PASSWORD_PLACEHOLDER" class="text" size="31" maxlength="31" id="newPwd" /></p>
  ```
- **Keywords:** usbUserAccount, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER.htm
- **Notes:** Local storage access credentials should be securely handled.

---
### base64_encoding

- **File/Directory Path:** `N/A`
- **Location:** `usr/bin/httpd (HIDDEN)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Discovered Base64 encoding-related function 'b64_encode', potentially used for encoding transmission of passwords or other sensitive information.
- **Keywords:** b64_encode, Authorization, Basic
- **Notes:** Need to confirm whether Base64 is used for REDACTED_PASSWORD_PLACEHOLDER transmission

---
