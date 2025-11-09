# TD-W8980_V1_150514 (16 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-FTP-REDACTED_PASSWORD_PLACEHOLDER:1234

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `./etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:First entry`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** Hardcoded FTP credentials found in plain text format 'REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER:flag1:flag2'. The credentials are stored without any encryption, which violates security best practices. The flags (1:1 or 0:0) might indicate account permissions or status, but their exact meaning would require further analysis of the vsftpd configuration.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** The credentials are stored in plain text, which is a security best practice violation. The file should be properly secured with appropriate permissions, and the credentials should be stored in an encrypted format or managed through a secure authentication system.

---
### REDACTED_PASSWORD_PLACEHOLDER-FTP-guest:guest

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `./etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:Second entry`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** Hardcoded FTP credentials in plaintext format 'REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER:flag1:flag2' were discovered. These credentials are stored without any encryption, violating security best practices. The flag bits (1:1 or 0:0) may indicate account permissions or status, but their exact meaning requires further analysis of the vsftpd configuration to determine.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** The credentials are stored in plain text, which is a security best practice violation. The file should be properly secured with appropriate permissions, and the credentials should be stored in an encrypted format or managed through a secure authentication system.

---
### REDACTED_PASSWORD_PLACEHOLDER-FTP-test:test

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `./etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER:Third entry`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** Hardcoded FTP credentials found in plain text format 'REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER:flag1:flag2'. The credentials are stored without any encryption, which violates security best practices. The flags (1:1 or 0:0) might indicate account permissions or status, but their exact meaning would require further analysis of the vsftpd configuration.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER:1234, guest:guest, test:test
- **Notes:** The credentials are stored in plain text, which is a security best practice violation. The file should be properly secured with appropriate permissions, and the credentials should be stored in an encrypted format or managed through a secure authentication system.

---
### hardcoded-REDACTED_PASSWORD_PLACEHOLDER-setPwd-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `web/frame/setPwd.htm`
- **Location:** `setPwd.htm (JavaScript function next())`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** The file contains hardcoded credentials with the default REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER'. In the function next(), the REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' is hardcoded and transmitted to the server via Base64 encoding. This may lead to unauthorized access if users do not change the default REDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  xmlHttpObj.open("POST", "http://192.168.1.1/cgi/setPwd?pwd=" + Base64Encoding("REDACTED_PASSWORD_PLACEHOLDER", true));
  ```
- **Keywords:** next(), Base64Encoding, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to enforce users to change default passwords and remove hardcoded default credentials. REDACTED_PASSWORD_PLACEHOLDER type: user REDACTED_PASSWORD_PLACEHOLDER.

---
### REDACTED_PASSWORD_PLACEHOLDER-management-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/reduced_data_model.xml`
- **Location:** `reduced_data_model.xml: REDACTED_SECRET_KEY_PLACEHOLDER section`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Hardcoded administrator credentials detected. In the REDACTED_SECRET_KEY_PLACEHOLDER section, the default REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER are both set to 'REDACTED_PASSWORD_PLACEHOLDER'. These credentials are used for device management interfaces and may lead to unauthorized access.
- **Code Snippet:**
  ```
  <REDACTED_PASSWORD_PLACEHOLDER t=s r=W l=256 d=REDACTED_PASSWORD_PLACEHOLDER />
  <REDACTED_PASSWORD_PLACEHOLDER t=s r=W l=256 d=REDACTED_PASSWORD_PLACEHOLDER tp=1 />
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Consider changing the default credentials to enhance security.

---
### hardcoded-REDACTED_PASSWORD_PLACEHOLDER-hostapd_wlan0-base64

- **File/Directory Path:** `sbin/hostapd_wlan0`
- **Location:** `./sbin/hostapd_wlan0: HIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A Base64-encoded string 'REDACTED_PASSWORD_PLACEHOLDER' was discovered, which decodes to 'REDACTED_PASSWORD_PLACEHOLDER:REDACTED_PASSWORD_PLACEHOLDER'. The Base64-encoded credentials reveal plaintext REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER upon decoding.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** hardcoded_credential

---
### hardcoded-credentials-httpd-REDACTED_PASSWORD_PLACEHOLDER-creds

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `./usr/bin/httpd:HIDDEN`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Hardcoded administrator REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER fields, potentially used for web interface authentication. REDACTED_PASSWORD_PLACEHOLDER type: REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER=%s
  REDACTED_PASSWORD_PLACEHOLDER=%s
  REDACTED_PASSWORD_PLACEHOLDER=%s
  REDACTED_PASSWORD_PLACEHOLDER=%s
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, oldPwd
- **Notes:** These fields may be used to store or transmit credentials for administrators and users. Further analysis is required to determine how these values are being utilized.

---
### hardcoded-credentials-REDACTED_SECRET_KEY_PLACEHOLDER-PPPoE

- **File/Directory Path:** `etc/default_config.xml`
- **Location:** `default_config.xml (WANDevice instance=3 > REDACTED_SECRET_KEY_PLACEHOLDER instance=1 > REDACTED_SECRET_KEY_PLACEHOLDER instance=1)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Hardcoded PPPoE REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER were found in REDACTED_SECRET_KEY_PLACEHOLDER configuration. These credentials are used for 3G USB connections and could potentially be exploited for unauthorized network access. The REDACTED_PASSWORD_PLACEHOLDER type is PPPoE authentication credentials.
- **Code Snippet:**
  ```
  <REDACTED_PASSWORD_PLACEHOLDER val=WAP@CINGULAR.COM />
  <REDACTED_PASSWORD_PLACEHOLDER val=CINGULAR1 />
  ```
- **Keywords:** REDACTED_SECRET_KEY_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, WAP@CINGULAR.COM, CINGULAR1
- **Notes:** These credentials appear to be default values for cellular network connections and may need to be modified in a production environment.

---
### REDACTED_PASSWORD_PLACEHOLDER-DES-hashed-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/REDACTED_PASSWORD_PLACEHOLDER.bak`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER.bak:1 (REDACTED_PASSWORD_PLACEHOLDER user entry)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The '.REDACTED_PASSWORD_PLACEHOLDER.bak' file contains a DES-based hashed REDACTED_PASSWORD_PLACEHOLDER for the 'REDACTED_PASSWORD_PLACEHOLDER' user (starting with $1$), which could be vulnerable to cracking attempts if weak REDACTED_PASSWORD_PLACEHOLDER was used. This backup REDACTED_PASSWORD_PLACEHOLDER file increases the attack surface.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** DES-based hashes are vulnerable to cracking attempts. It is recommended to remove or protect backup REDACTED_PASSWORD_PLACEHOLDER files, and if still in use, change the administrator REDACTED_PASSWORD_PLACEHOLDER.

---
### REDACTED_PASSWORD_PLACEHOLDER-DES-hashed-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/vsftpd_REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `.REDACTED_PASSWORD_PLACEHOLDER.bak:1 (REDACTED_PASSWORD_PLACEHOLDER user entry)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The '.REDACTED_PASSWORD_PLACEHOLDER.bak' file contains a DES-based hashed REDACTED_PASSWORD_PLACEHOLDER for the 'REDACTED_PASSWORD_PLACEHOLDER' user (starting with $1$), which could be vulnerable to cracking attempts if weak REDACTED_PASSWORD_PLACEHOLDER was used. This backup REDACTED_PASSWORD_PLACEHOLDER file increases the attack surface.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER.bak, REDACTED_PASSWORD_PLACEHOLDER, $1$$iC.REDACTED_SECRET_KEY_PLACEHOLDER/
- **Notes:** DES-based hash is vulnerable to cracking attempts. Recommend removing or securing the backup REDACTED_PASSWORD_PLACEHOLDER file and changing the REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_PLACEHOLDER if still in use.

---
### hardcoded-credentials-StorageService-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc/default_config.xml`
- **Location:** `default_config.xml (Services > StorageService > UserAccount instance=1)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Default administrator account credentials were found in the StorageService configuration. These weak credentials could be used for unauthorized device access. The REDACTED_PASSWORD_PLACEHOLDER type is administrator account credentials.
- **Code Snippet:**
  ```
  <REDACTED_PASSWORD_PLACEHOLDER val=REDACTED_PASSWORD_PLACEHOLDER />
  <REDACTED_PASSWORD_PLACEHOLDER val=REDACTED_PASSWORD_PLACEHOLDER />
  ```
- **Keywords:** StorageService, UserAccount, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is a common security issue; it is recommended to enforce changing the default credentials.

---
### insecure-transmission-setPwd-base64

- **File/Directory Path:** `web/frame/setPwd.htm`
- **Location:** `setPwd.htm (JavaScript functions doSetPassword() and next())`
- **Risk Score:** 7.0
- **Confidence:** 9.0
- **Description:** The REDACTED_PASSWORD_PLACEHOLDER is transmitted via Base64 encoding but without HTTPS or other encryption methods. Base64 encoding is not encryption and can be easily decoded. This may result in the REDACTED_PASSWORD_PLACEHOLDER being intercepted during transmission.
- **Code Snippet:**
  ```
  xmlHttpObj.open("POST", "http://192.168.1.1/cgi/setPwd?pwd=" + Base64Encoding($("newPwd").value) , true);
  ```
- **Keywords:** Base64Encoding, doSetPassword(), next()
- **Notes:** It is recommended to use the HTTPS protocol for REDACTED_PASSWORD_PLACEHOLDER transmission and consider stronger encryption methods. REDACTED_PASSWORD_PLACEHOLDER type: User REDACTED_PASSWORD_PLACEHOLDER.

---
### REDACTED_PASSWORD_PLACEHOLDER-snmp-community

- **File/Directory Path:** `etc/reduced_data_model.xml`
- **Location:** `reduced_data_model.xml: SnmpCfg section`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** Hardcoded SNMP community strings detected. ROCommunity is set to 'public' and RWCommunity is set to 'private'. These default strings could potentially be exploited for unauthorized SNMP access.
- **Code Snippet:**
  ```
  <ROCommunity t=s r=W l=64 d=public h=1 />
  <RWCommunity t=s r=W l=64 d=private h=1 />
  ```
- **Keywords:** SnmpCfg, ROCommunity, RWCommunity, public, private
- **Notes:** It is recommended to change the SNMP community string or disable the SNMP service.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-ftp-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `./usr/bin/vsftpd:N/A (binary file)`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Hardcoded REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER combination detected: 'REDACTED_PASSWORD_PLACEHOLDER' and '1234'. These may be default credentials used for FTP login.
- **Code Snippet:**
  ```
  N/A (binary file)
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, 1234, FTP
- **Notes:** It is recommended to verify whether these credentials are actually used for FTP service login.

---
### hardcoded-REDACTED_PASSWORD_PLACEHOLDER-hostapd_wlan0-password123

- **File/Directory Path:** `sbin/hostapd_wlan0`
- **Location:** `./sbin/hostapd_wlan0: HIDDEN`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A potential hardcoded REDACTED_PASSWORD_PLACEHOLDER 'password123' was identified within the string output. Further verification is required to determine if this REDACTED_PASSWORD_PLACEHOLDER is actively in use.
- **Code Snippet:**
  ```
  N/A (HIDDEN)
  ```
- **Keywords:** password123
- **Notes:** Further verification is required to determine if the REDACTED_PASSWORD_PLACEHOLDER is in actual use. REDACTED_PASSWORD_PLACEHOLDER type: user REDACTED_PASSWORD_PLACEHOLDER.

---
### REDACTED_PASSWORD_PLACEHOLDER-wifi-presharedkey

- **File/Directory Path:** `etc/reduced_data_model.xml`
- **Location:** `reduced_data_model.xml: REDACTED_SECRET_KEY_PLACEHOLDER section`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** Hard-coded Wi-Fi pre-shared REDACTED_PASSWORD_PLACEHOLDER detected. The X_TPLINK_PreSharedKey field may contain the encryption REDACTED_PASSWORD_PLACEHOLDER for the Wi-Fi network.
- **Code Snippet:**
  ```
  <X_TPLINK_PreSharedKey t=s r=W l=65 tp=1 cp=1 />
  ```
- **Keywords:** X_TPLINK_PreSharedKey, tp=1, cp=1
- **Notes:** Consider changing the Wi-Fi pre-shared REDACTED_PASSWORD_PLACEHOLDER to enhance network security.

---
