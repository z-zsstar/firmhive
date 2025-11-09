# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (28 alerts)

---

### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-RSA-private-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `webroot_ro/pem/privkeySrv.pem`
- **Location:** `webroot_ro/pem/privkeySrv.pem`
- **Risk Score:** 10.0
- **Confidence:** 10.0
- **Description:** A hardcoded RSA private REDACTED_PASSWORD_PLACEHOLDER was found in the file 'webroot_ro/pem/privkeySrv.pem'. This is highly sensitive information typically used for encrypted communications (e.g., HTTPS, SSH). Leakage of the private REDACTED_PASSWORD_PLACEHOLDER may lead to man-in-the-middle attacks or data decryption.
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
  ...
  ```
- **Keywords:** privkeySrv.pem, RSA PRIVATE REDACTED_PASSWORD_PLACEHOLDER, PEM
- **Notes:** It is recommended to immediately replace this private REDACTED_PASSWORD_PLACEHOLDER and ensure the new private REDACTED_PASSWORD_PLACEHOLDER is not hardcoded in the firmware. Additionally, check whether any services are currently using this private REDACTED_PASSWORD_PLACEHOLDER and assess the potential security impact. REDACTED_PASSWORD_PLACEHOLDER type: SSH private REDACTED_PASSWORD_PLACEHOLDER.

---
### wep-REDACTED_PASSWORD_PLACEHOLDER-default

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `default.cfg`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** Default WEP REDACTED_PASSWORD_PLACEHOLDER '12345' detected. WEP encryption has been proven insecure and may allow wireless networks to be easily compromised.
- **Code Snippet:**
  ```
  wl2g.ssid0.wep_key1=12345
  wl5g.ssid0.wep_key1=12345
  ```
- **Keywords:** wl2g.ssid0.wep_key1, wl5g.ssid0.wep_key1
- **Notes:** It is strongly recommended to disable WEP encryption and switch to more secure WPA2 or WPA3 encryption.

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-shadow

- **File/Directory Path:** `etc_ro/shadow`
- **Location:** `etc_ro/shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 8.25
- **Description:** configuration_load
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER:14319::::::
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, $1$OVhtCyFa$REDACTED_PASSWORD_PLACEHOLDER, shadow
- **Notes:** The MD5 crypt hash could be vulnerable to brute force attacks. Recommend checking if this is the active REDACTED_PASSWORD_PLACEHOLDER for the REDACTED_PASSWORD_PLACEHOLDER account and consider changing it to a more secure hash algorithm like SHA-512 (indicated by $6$ prefix).

---
### hardcoded-REDACTED_PASSWORD_PLACEHOLDER-login-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `webroot_ro/login.html`
- **Location:** `webroot_ro/login.html`
- **Risk Score:** 8.0
- **Confidence:** 10.0
- **Description:** Hardcoded credentials were found in the 'webroot_ro/login.html' file. The file contains a hidden input field where both the REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER are set to 'REDACTED_PASSWORD_PLACEHOLDER'. This poses a significant security risk as attackers can easily obtain these credentials.
- **Code Snippet:**
  ```
  <input type="hidden" id="REDACTED_PASSWORD_PLACEHOLDER" value="REDACTED_PASSWORD_PLACEHOLDER">
  <input type="hidden" id="REDACTED_PASSWORD_PLACEHOLDER" value="REDACTED_PASSWORD_PLACEHOLDER">
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** Recommend modifying these hardcoded credentials and adopting a more secure authentication mechanism. REDACTED_PASSWORD_PLACEHOLDER type: user REDACTED_PASSWORD_PLACEHOLDER.

---
### REDACTED_PASSWORD_PLACEHOLDER-pptp-client-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Location:** `REDACTED_SECRET_KEY_PLACEHOLDER.txt`
- **Risk Score:** 8.0
- **Confidence:** 10.0
- **Description:** The file 'REDACTED_SECRET_KEY_PLACEHOLDER.txt' contains hardcoded REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER. The REDACTED_PASSWORD_PLACEHOLDER '123' and REDACTED_PASSWORD_PLACEHOLDER '456' are stored in plaintext, potentially used for PPTP client authentication. It is recommended to encrypt these credentials or remove them from the configuration file.
- **Code Snippet:**
  ```
  "REDACTED_PASSWORD_PLACEHOLDER":"123",
  "REDACTED_PASSWORD_PLACEHOLDER":"456"
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** REDACTED_PASSWORD_PLACEHOLDER Type: PPTP Client REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER

---
### REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER-default

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `default.cfg`
- **Risk Score:** 8.0
- **Confidence:** 9.5
- **Description:** Default administrator credentials detected: REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' and blank REDACTED_PASSWORD_PLACEHOLDER. This may lead to unauthorized access to the router management interface.
- **Code Snippet:**
  ```
  sys.REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER
  REDACTED_PASSWORD_PLACEHOLDER=
  ```
- **Keywords:** sys.REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** It is recommended to enforce users to change their REDACTED_PASSWORD_PLACEHOLDER upon first login.

---
### REDACTED_PASSWORD_PLACEHOLDER-pptp-mrwho1

- **File/Directory Path:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Location:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** Hardcoded PPTP VPN REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER combination found. The REDACTED_PASSWORD_PLACEHOLDER 'mrwho1' and REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' are stored in plaintext within the configuration file. These credentials are used for PPTP VPN connections, with the connection status being enabled (connsta=1).
- **Code Snippet:**
  ```
  {"connsta": "1", "REDACTED_PASSWORD_PLACEHOLDER": "mrwho1", "REDACTED_PASSWORD_PLACEHOLDER": "REDACTED_PASSWORD_PLACEHOLDER", "netEn": "1", "serverIp": "192.168.0.12", "serverMask": "255.255.255.0", "remark": "pptprule", "enable": "1"}
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, connsta
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER is enabled and may be directly exploited by attackers.

---
### REDACTED_PASSWORD_PLACEHOLDER-pptp-mrwho3

- **File/Directory Path:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Location:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** Hardcoded PPTP VPN REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER combination found. The REDACTED_PASSWORD_PLACEHOLDER 'mrwho3' and REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' are stored in plaintext within the configuration file. These credentials are used for PPTP VPN connections, with the connection status shown as enabled (connsta=1).
- **Code Snippet:**
  ```
  {"connsta": "1", "REDACTED_PASSWORD_PLACEHOLDER": "mrwho3", "REDACTED_PASSWORD_PLACEHOLDER": "REDACTED_PASSWORD_PLACEHOLDER", "netEn": "1", "serverIp": "192.168.0.12", "serverMask": "255.255.255.0", "remark": "pptprule", "enable": "1"}
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, connsta
- **Notes:** The REDACTED_PASSWORD_PLACEHOLDER is enabled and could be directly exploited by attackers.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:1`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** The 'REDACTED_PASSWORD_PLACEHOLDER' user REDACTED_PASSWORD_PLACEHOLDER hash is hardcoded in the 'etc_ro/REDACTED_PASSWORD_PLACEHOLDER' file using insecure MD5 algorithm ($1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1). MD5 is considered insecure and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing. This poses a security risk as it can be targeted for offline cracking attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, password_hash
- **Notes:** MD5 is considered insecure and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:2`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** The 'REDACTED_PASSWORD_PLACEHOLDER' user REDACTED_PASSWORD_PLACEHOLDER hash is hardcoded in the 'etc_ro/REDACTED_PASSWORD_PLACEHOLDER' file using insecure DES algorithm (6HgsSsJIEOc2U). DES is extremely weak and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing. This poses a security risk as it can be targeted for offline cracking attacks.
- **Code Snippet:**
  ```
  REDACTED_PASSWORD_PLACEHOLDER:6HgsSsJIEOc2U:0:0:REDACTED_PASSWORD_PLACEHOLDER:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, REDACTED_PASSWORD_PLACEHOLDER, password_hash
- **Notes:** DES is extremely weak and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-support-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:3`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** The 'support' user REDACTED_PASSWORD_PLACEHOLDER hash is hardcoded in the 'etc_ro/REDACTED_PASSWORD_PLACEHOLDER' file using insecure DES algorithm (Ead09Ca6IhzZY). DES is extremely weak and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing. This poses a security risk as it can be targeted for offline cracking attacks.
- **Code Snippet:**
  ```
  support:Ead09Ca6IhzZY:0:0:support:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, support, password_hash
- **Notes:** DES is extremely weak and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-user-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:4`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** The 'user' user REDACTED_PASSWORD_PLACEHOLDER hash is hardcoded in the 'etc_ro/REDACTED_PASSWORD_PLACEHOLDER' file using insecure DES algorithm (tGqcT.qjxbEik). DES is extremely weak and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing. This poses a security risk as it can be targeted for offline cracking attacks.
- **Code Snippet:**
  ```
  user:tGqcT.qjxbEik:0:0:user:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, user, password_hash
- **Notes:** DES is extremely weak and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-nobody-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER`
- **Location:** `etc_ro/REDACTED_PASSWORD_PLACEHOLDER:5`
- **Risk Score:** 8.0
- **Confidence:** 8.75
- **Description:** The 'nobody' user REDACTED_PASSWORD_PLACEHOLDER hash is hardcoded in the 'etc_ro/REDACTED_PASSWORD_PLACEHOLDER' file using insecure DES algorithm (VBcCXSNG7zBAY). DES is extremely weak and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing. This poses a security risk as it can be targeted for offline cracking attacks.
- **Code Snippet:**
  ```
  nobody:VBcCXSNG7zBAY:0:0:nobody:/REDACTED_PASSWORD_PLACEHOLDER:/bin/sh
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER, nobody, password_hash
- **Notes:** DES is extremely weak and should not be used for REDACTED_PASSWORD_PLACEHOLDER hashing.

---
### REDACTED_PASSWORD_PLACEHOLDER-WPS-REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `webroot_ro/nvram_default.cfg`
- **Location:** `webroot_ro/nvram_default.cfg`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** The WPS device REDACTED_PASSWORD_PLACEHOLDER is hardcoded as 'REDACTED_PASSWORD_PLACEHOLDER'. The WPS REDACTED_PASSWORD_PLACEHOLDER is used for Wi-Fi Protected Setup, and if obtained by an attacker, it could allow unauthorized devices to access the network.
- **Code Snippet:**
  ```
  WPSHIDDENPINHIDDEN: REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** hardcoded credentials, type WPS REDACTED_PASSWORD_PLACEHOLDER

---
### hardcoded-credentials-libcloud-email

- **File/Directory Path:** `lib/libcloud.so`
- **Location:** `lib/libcloud.so`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A hardcoded email address 'test@yyb.com' was found in the file 'lib/libcloud.so', potentially used for authentication or testing purposes. These findings indicate potential security risks, as attackers could exploit these hardcoded credentials to gain unauthorized access.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** test@yyb.com, tenda, login_param, up_pwd_param, authkey, secret_init, secret_update, secret_fini, aes_md5_fini
- **Notes:** configuration_load

---
### hardcoded-credentials-libcloud-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `lib/libcloud.so`
- **Location:** `lib/libcloud.so`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A hardcoded REDACTED_PASSWORD_PLACEHOLDER 'tenda' was found in the file 'lib/libcloud.so', which may be a default or backdoor REDACTED_PASSWORD_PLACEHOLDER. These findings indicate potential security risks, as attackers could exploit these hardcoded credentials to gain unauthorized access.
- **Code Snippet:**
  ```
  N/A
  ```
- **Keywords:** test@yyb.com, tenda, login_param, up_pwd_param, authkey, secret_init, secret_update, secret_fini, aes_md5_fini
- **Notes:** configuration_load

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded-REDACTED_PASSWORD_PLACEHOLDER-auth.txt

- **File/Directory Path:** `bin/dhttpd`
- **Location:** `Strings output (line containing user/REDACTED_PASSWORD_PLACEHOLDER definition)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** Hardcoded credentials found in the file, REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' and REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' defined in the authentication configuration template. This may be a default REDACTED_PASSWORD_PLACEHOLDER that can be used for authentication.
- **Code Snippet:**
  ```
  user name=REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER roles=administrator,purchase
  ```
- **Keywords:** auth.txt, user name=REDACTED_PASSWORD_PLACEHOLDER REDACTED_PASSWORD_REDACTED_PASSWORD_PLACEHOLDER_PASSWORD_PLACEHOLDER, roles=administrator
- **Notes:** This appears to be a default REDACTED_PASSWORD_PLACEHOLDER, likely part of an authentication configuration template. The REDACTED_PASSWORD_PLACEHOLDER type is a REDACTED_PASSWORD_PLACEHOLDER-REDACTED_PASSWORD_PLACEHOLDER pair.

---
### REDACTED_PASSWORD_PLACEHOLDER-hardcoded_password-httpd

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd:0 (strings output)`
- **Risk Score:** 8.0
- **Confidence:** 6.75
- **Description:** hardcoded_credential
- **Code Snippet:**
  ```
  Hardcoded REDACTED_PASSWORD_PLACEHOLDER: *j7a(L#REDACTED_SECRET_KEY_PLACEHOLDER;Ss;d)(*&^#@$a2s0i3g
  ```
- **Keywords:** *j7a(L#REDACTED_SECRET_KEY_PLACEHOLDER;Ss;d)(*&^#@$a2s0i3g
- **Notes:** hardcoded_credential

---
### REDACTED_PASSWORD_PLACEHOLDER-vpn-configuration-templates

- **File/Directory Path:** `lib/libtpi.so`
- **Location:** `Strings output`
- **Risk Score:** 7.5
- **Confidence:** 6.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  Not provided in original finding
  ```
- **Keywords:** user "%s", REDACTED_PASSWORD_PLACEHOLDER "%s", /etc/xl2tp/xl2tpd.option.wan%d, tpi_vpn_l2tp_set, pptp_server
- **Notes:** configuration_load

---
### REDACTED_PASSWORD_PLACEHOLDER-user-default

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 9.0
- **Description:** Default basic user credentials detected: REDACTED_PASSWORD_PLACEHOLDER 'user' and REDACTED_PASSWORD_PLACEHOLDER 'user'. This may lead to unauthorized access to the router management interface.
- **Code Snippet:**
  ```
  sys.baseREDACTED_PASSWORD_PLACEHOLDER=user
  sys.baseuserpass=user
  ```
- **Keywords:** sys.baseREDACTED_PASSWORD_PLACEHOLDER, sys.baseuserpass
- **Notes:** It is recommended to enforce users to change their REDACTED_PASSWORD_PLACEHOLDER upon first login.

---
### wifi-REDACTED_PASSWORD_PLACEHOLDER-default

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 9.0
- **Description:** The default WPA2-PSK wireless network REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' has been detected. This may lead to unauthorized access to the wireless network.
- **Code Snippet:**
  ```
  wl2g.ssid0.wpapsk_psk=REDACTED_PASSWORD_PLACEHOLDER
  wl5g.ssid0.wpapsk_psk=REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** wl2g.ssid0.wpapsk_psk, wl5g.ssid0.wpapsk_psk
- **Notes:** It is recommended to enforce users to change the wireless network REDACTED_PASSWORD_PLACEHOLDER upon initial connection.

---
### ftp-REDACTED_PASSWORD_PLACEHOLDER-default

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** Default FTP service credentials detected: REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' and REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER'. This may lead to unauthorized access to the FTP service.
- **Code Snippet:**
  ```
  usb.ftp.user=REDACTED_PASSWORD_PLACEHOLDER
  usb.ftp.pwd=REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** usb.ftp.user, usb.ftp.pwd
- **Notes:** It is recommended to enforce users to change default credentials when enabling the FTP service.

---
### samba-REDACTED_PASSWORD_PLACEHOLDER-default

- **File/Directory Path:** `webroot_ro/default.cfg`
- **Location:** `default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** Default credentials detected for Samba service: REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER' and REDACTED_PASSWORD_PLACEHOLDER 'REDACTED_PASSWORD_PLACEHOLDER'. This may lead to unauthorized access to shared files.
- **Code Snippet:**
  ```
  usb.samba.user=REDACTED_PASSWORD_PLACEHOLDER
  usb.samba.pwd=REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** usb.samba.user, usb.samba.pwd
- **Notes:** It is recommended to enforce users to change the default credentials when enabling the Samba service.

---
### REDACTED_PASSWORD_PLACEHOLDER-ddns-credentials

- **File/Directory Path:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Location:** `webroot_REDACTED_PASSWORD_PLACEHOLDER.txt`
- **Risk Score:** 7.0
- **Confidence:** 8.5
- **Description:** configuration_load
- **Code Snippet:**
  ```
  "ddnsUser":"123",
  "ddnsPwd":"456"
  ```
- **Keywords:** ddnsUser, ddnsPwd
- **Notes:** configuration_load

---
### REDACTED_PASSWORD_PLACEHOLDER-WPS-StaticPIN-REDACTED_PASSWORD_PLACEHOLDER

- **File/Directory Path:** `webroot_ro/nvram_default.cfg`
- **Location:** `webroot_ro/nvram_default.cfg`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** The WPS static REDACTED_PASSWORD_PLACEHOLDER is hardcoded as 'REDACTED_PASSWORD_PLACEHOLDER'. This is a default static REDACTED_PASSWORD_PLACEHOLDER that is easily guessed and exploited.
- **Code Snippet:**
  ```
  WPSHIDDENPINHIDDEN: REDACTED_PASSWORD_PLACEHOLDER
  ```
- **Keywords:** wps_sta_pin
- **Notes:** hard-coded credentials, type WPS Static REDACTED_PASSWORD_PLACEHOLDER

---
### REDACTED_PASSWORD_PLACEHOLDER-pppoe-plaintext-storage

- **File/Directory Path:** `bin/pppoeconfig.sh`
- **Location:** `bin/pppoeconfig.sh`
- **Risk Score:** 7.0
- **Confidence:** 7.5
- **Description:** The script 'bin/pppoeconfig.sh' is used to configure PPPoE connections, accepting REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER as parameters and storing these credentials in plaintext within the configuration file '/etc/ppp/option.pppoe.wan$UNIT'. Although the script itself does not hardcode credentials, it stores user-provided credentials in plaintext within configuration files, posing an information leakage risk. Attackers who gain access to these configuration files could obtain PPPoE credentials.
- **Code Snippet:**
  ```
  echo user \'$USER\' >>$CONFIG_FILE
  echo REDACTED_PASSWORD_PLACEHOLDER \'$PSWD\' >>$CONFIG_FILE
  ```
- **Keywords:** USER, PSWD, CONFIG_FILE, /etc/ppp/option.pppoe.wan$UNIT
- **Notes:** It is recommended to check whether the generated configuration file '/etc/ppp/option.pppoe.wan$UNIT' contains hardcoded credentials. Additionally, it is advisable to store passwords using encryption rather than in plain text.

---
### REDACTED_PASSWORD_PLACEHOLDER-pppoe-configuration-templates

- **File/Directory Path:** `lib/libtpi.so`
- **Location:** `Strings output`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** PPPoE credentials were found in configuration strings. These strings display the REDACTED_PASSWORD_PLACEHOLDER and REDACTED_PASSWORD_PLACEHOLDER patterns configured for PPPoE connections, which may represent hardcoded credentials. The credentials appear in the context of PPPoE client setup scripts. They seem to be part of configuration templates rather than actual hardcoded values. However, if these templates are used without proper REDACTED_PASSWORD_PLACEHOLDER substitution, it could lead to REDACTED_PASSWORD_PLACEHOLDER exposure.
- **Code Snippet:**
  ```
  Not provided in original finding
  ```
- **Keywords:** user "%s", REDACTED_PASSWORD_PLACEHOLDER "%s", /etc/ppp/option.pppoe.wan%d, tpi_pppoec_create_option_file
- **Notes:** configuration_load

---
### REDACTED_PASSWORD_PLACEHOLDER-base64_REDACTED_PASSWORD_PLACEHOLDER-httpd

- **File/Directory Path:** `bin/httpd`
- **Location:** `bin/httpd:0 (strings output)`
- **Risk Score:** 7.0
- **Confidence:** 6.5
- **Description:** A Base64-encoded string was discovered in the string output of 'bin/httpd'. After decoding, it was found to be 'REDACTED_PASSWORD_PLACEHOLDER'. This REDACTED_PASSWORD_PLACEHOLDER may be used for authentication purposes.
- **Code Snippet:**
  ```
  Base64 encoded REDACTED_PASSWORD_PLACEHOLDER: YWRtaW4= (decodes to 'REDACTED_PASSWORD_PLACEHOLDER')
  ```
- **Keywords:** YWRtaW4=, REDACTED_PASSWORD_PLACEHOLDER
- **Notes:** hardcoded_credential

---
